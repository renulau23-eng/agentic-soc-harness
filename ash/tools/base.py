"""Tool model and registry.

A tool is a typed Python callable with a JSON schema, a risk tier and a
required permission. Nothing executes a tool except the harness executor,
which enforces schema validation, RBAC, policy and audit.
"""

from __future__ import annotations

import enum
import inspect
import types
import typing
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, get_args, get_origin, get_type_hints

from ash.core.errors import ToolValidationError
from ash.core.types import RiskTier, ToolSpec

_PY_TO_JSON = {str: "string", int: "integer", float: "number", bool: "boolean", dict: "object", list: "array"}


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    fn: Callable[..., Any]
    risk_tier: RiskTier = RiskTier.LOW
    permission: str = "tools:execute:low"
    tags: list[str] = field(default_factory=list)
    accepts_context: bool = False

    def spec(self) -> ToolSpec:
        return ToolSpec(
            name=self.name,
            description=self.description,
            parameters=self.parameters,
            risk_tier=self.risk_tier,
            permission=self.permission,
            tags=self.tags,
        )

    def validate(self, args: dict[str, Any]) -> dict[str, Any]:
        return validate_against_schema(self.name, self.parameters, args)


def default_permission(tier: RiskTier) -> str:
    return f"tools:execute:{tier.value}"


def tool(
    name: str | None = None,
    *,
    description: str | None = None,
    risk_tier: RiskTier = RiskTier.LOW,
    permission: str | None = None,
    tags: list[str] | None = None,
) -> Callable[[Callable[..., Any]], Tool]:
    """Turn a typed function into a ``Tool``; schema is derived from annotations.

    If the function's first parameter is named ``ctx`` it receives the
    ``ToolContext`` (connectors, principal, case id) at execution time.
    """

    def deco(fn: Callable[..., Any]) -> Tool:
        tool_name = name or fn.__name__
        params, accepts_ctx = _schema_from_signature(fn)
        return Tool(
            name=tool_name,
            description=(description or inspect.getdoc(fn) or tool_name).strip(),
            parameters=params,
            fn=fn,
            risk_tier=risk_tier,
            permission=permission or default_permission(risk_tier),
            tags=tags or [],
            accepts_context=accepts_ctx,
        )

    return deco


def _schema_from_signature(fn: Callable[..., Any]) -> tuple[dict[str, Any], bool]:
    sig = inspect.signature(fn)
    hints = get_type_hints(fn)
    props: dict[str, Any] = {}
    required: list[str] = []
    accepts_ctx = False
    for pname, p in sig.parameters.items():
        if pname == "ctx":
            accepts_ctx = True
            continue
        ann = hints.get(pname, str)
        props[pname] = _json_type(ann)
        if p.default is inspect.Parameter.empty:
            required.append(pname)
        else:
            props[pname]["default"] = p.default
    schema: dict[str, Any] = {"type": "object", "properties": props, "additionalProperties": False}
    if required:
        schema["required"] = required
    return schema, accepts_ctx


def _json_type(ann: Any) -> dict[str, Any]:
    origin = get_origin(ann)
    if origin is typing.Union or origin is types.UnionType:
        args = [a for a in get_args(ann) if a is not type(None)]
        return _json_type(args[0]) if args else {"type": "string"}
    if origin in (list, typing.List):  # noqa: UP006
        inner = get_args(ann)
        return {"type": "array", "items": _json_type(inner[0]) if inner else {"type": "string"}}
    if origin in (dict, typing.Dict):  # noqa: UP006
        return {"type": "object"}
    if isinstance(ann, type) and issubclass(ann, enum.Enum):
        return {"type": "string", "enum": [e.value for e in ann]}
    return {"type": _PY_TO_JSON.get(ann, "string")}


def validate_against_schema(tool_name: str, schema: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
    """Minimal, dependency-free JSON-schema validation for object schemas."""
    if not isinstance(args, dict):
        raise ToolValidationError(f"{tool_name}: arguments must be an object")
    props = schema.get("properties", {})
    if schema.get("additionalProperties") is False:
        unknown = set(args) - set(props)
        if unknown:
            raise ToolValidationError(f"{tool_name}: unknown arguments {sorted(unknown)}")
    for req in schema.get("required", []):
        if req not in args:
            raise ToolValidationError(f"{tool_name}: missing required argument '{req}'")
    cleaned: dict[str, Any] = {}
    for k, spec in props.items():
        if k not in args:
            if "default" in spec:
                cleaned[k] = spec["default"]
            continue
        cleaned[k] = _coerce(tool_name, k, spec, args[k])
    return cleaned


def _coerce(tool_name: str, key: str, spec: dict[str, Any], value: Any) -> Any:
    t = spec.get("type")
    if "enum" in spec and value not in spec["enum"]:
        raise ToolValidationError(f"{tool_name}: '{key}' must be one of {spec['enum']}")
    if t == "string":
        if not isinstance(value, str):
            value = str(value)
    elif t == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            try:
                value = int(value)
            except (TypeError, ValueError) as exc:
                raise ToolValidationError(f"{tool_name}: '{key}' must be an integer") from exc
    elif t == "number":
        try:
            value = float(value)
        except (TypeError, ValueError) as exc:
            raise ToolValidationError(f"{tool_name}: '{key}' must be a number") from exc
    elif t == "boolean":
        if isinstance(value, str):
            value = value.lower() in {"1", "true", "yes"}
        value = bool(value)
    elif t == "array" and not isinstance(value, list):
        raise ToolValidationError(f"{tool_name}: '{key}' must be an array")
    elif t == "object" and not isinstance(value, dict):
        raise ToolValidationError(f"{tool_name}: '{key}' must be an object")
    return value


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, t: Tool, *, replace: bool = False) -> Tool:
        if t.name in self._tools and not replace:
            raise ValueError(f"tool '{t.name}' already registered")
        self._tools[t.name] = t
        return t

    def register_many(self, tools: list[Tool]) -> None:
        for t in tools:
            self.register(t)

    def get(self, name: str) -> Tool:
        try:
            return self._tools[name]
        except KeyError:
            raise KeyError(f"unknown tool '{name}'") from None

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def names(self) -> list[str]:
        return sorted(self._tools)

    def specs(self, names: list[str] | None = None) -> list[ToolSpec]:
        selected = self._tools.values() if names is None else [self._tools[n] for n in names if n in self._tools]
        return [t.spec() for t in selected]

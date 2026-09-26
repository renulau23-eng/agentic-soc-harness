"""Guardrail hook: the integration seam for the protective plane
(AgentPEP, LLM Firewall, Thoth semantic firewall).

Three interception points: before a prompt reaches a model, after the model
answers, and before a tool executes. A guardrail may pass, mutate, or block.
Reference implementations: a no-op, a prompt-injection heuristic, a secret
redactor, and a webhook client for an external policy enforcement point.
"""

from __future__ import annotations

import re
from typing import Any, Protocol

import httpx

from ash.core.errors import GuardrailBlocked
from ash.core.types import Message, ModelResponse
from ash.observability import get_logger, metrics

log = get_logger(__name__)


class Guardrail(Protocol):
    name: str

    def before_model(self, messages: list[Message], meta: dict[str, Any]) -> list[Message]: ...
    def after_model(self, response: ModelResponse, meta: dict[str, Any]) -> ModelResponse: ...
    def before_tool(self, tool: str, args: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]: ...


class NoopGuardrail:
    name = "noop"

    def before_model(self, messages: list[Message], meta: dict[str, Any]) -> list[Message]:
        return messages

    def after_model(self, response: ModelResponse, meta: dict[str, Any]) -> ModelResponse:
        return response

    def before_tool(self, tool: str, args: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
        return args


_INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior|above) instructions",
    r"you are now (?:in )?(developer|dan|god) mode",
    r"disregard (your|the) (system|safety) (prompt|rules)",
    r"reveal (your|the) (system prompt|instructions)",
]


class PromptInjectionGuardrail:
    """Heuristic detector for tool results or alerts carrying injected instructions.
    Stand-in for Thoth; production deployments point the webhook at Thoth."""

    name = "prompt_injection_heuristic"

    def __init__(self, block: bool = False):
        self.block = block
        self._re = re.compile("|".join(_INJECTION_PATTERNS), re.I)

    def before_model(self, messages: list[Message], meta: dict[str, Any]) -> list[Message]:
        out: list[Message] = []
        for m in messages:
            if m.role.value in {"user", "tool"} and m.content and self._re.search(m.content):
                metrics.inc("ash_guardrail_hits_total", guardrail=self.name, stage="before_model")
                if self.block:
                    raise GuardrailBlocked("before_model", "prompt injection pattern detected")
                m = m.model_copy(
                    update={
                        "content": "[REDACTED: suspected prompt injection]\n" + self._re.sub("[removed]", m.content)
                    }
                )
            out.append(m)
        return out

    def after_model(self, response: ModelResponse, meta: dict[str, Any]) -> ModelResponse:
        return response

    def before_tool(self, tool: str, args: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
        return args


class SecretRedactionGuardrail:
    name = "secret_redaction"
    _patterns = [
        re.compile(r"(?i)(api[_-]?key|password|secret|token)\s*[=:]\s*['\"]?([^\s'\"]{6,})"),
        re.compile(r"\b[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"),  # JWT-like
    ]

    def _scrub(self, text: str) -> str:
        for p in self._patterns:
            text = p.sub(lambda m: (m.group(1) + "=***") if m.lastindex and m.lastindex >= 2 else "***", text)
        return text

    def before_model(self, messages: list[Message], meta: dict[str, Any]) -> list[Message]:
        return [m.model_copy(update={"content": self._scrub(m.content)}) if m.content else m for m in messages]

    def after_model(self, response: ModelResponse, meta: dict[str, Any]) -> ModelResponse:
        if response.content:
            response.content = self._scrub(response.content)
        return response

    def before_tool(self, tool: str, args: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
        return args


class WebhookGuardrail:
    """Calls an external policy enforcement point (AgentPEP / LLM Firewall).

    Request:  {"stage": "...", "payload": {...}, "meta": {...}}
    Response: {"allow": bool, "reason": str, "payload": <optional mutated payload>}
    """

    name = "webhook"

    def __init__(self, url: str, timeout_s: float = 5.0, fail_open: bool = False):
        self.url = url
        self.fail_open = fail_open
        self._client = httpx.Client(timeout=timeout_s)

    def _call(self, stage: str, payload: Any, meta: dict[str, Any]) -> Any:
        try:
            r = self._client.post(self.url, json={"stage": stage, "payload": payload, "meta": meta})
            r.raise_for_status()
            data = r.json()
        except (httpx.HTTPError, ValueError) as exc:
            if self.fail_open:
                log.warning("guardrail webhook unreachable; fail-open", error=str(exc))
                return payload
            raise GuardrailBlocked(stage, f"policy enforcement point unreachable: {exc}") from exc
        if not data.get("allow", False):
            metrics.inc("ash_guardrail_hits_total", guardrail=self.name, stage=stage)
            raise GuardrailBlocked(stage, data.get("reason", "blocked by policy enforcement point"))
        return data.get("payload", payload)

    def before_model(self, messages: list[Message], meta: dict[str, Any]) -> list[Message]:
        out = self._call("before_model", [m.model_dump() for m in messages], meta)
        return [Message(**m) for m in out]

    def after_model(self, response: ModelResponse, meta: dict[str, Any]) -> ModelResponse:
        return ModelResponse(**self._call("after_model", response.model_dump(), meta))

    def before_tool(self, tool: str, args: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
        return self._call("before_tool", {"tool": tool, "args": args}, meta).get("args", args)


class GuardrailChain:
    def __init__(self, guardrails: list[Guardrail] | None = None):
        self.guardrails: list[Guardrail] = list(guardrails or [])

    def before_model(self, messages: list[Message], meta: dict[str, Any]) -> list[Message]:
        for g in self.guardrails:
            messages = g.before_model(messages, meta)
        return messages

    def after_model(self, response: ModelResponse, meta: dict[str, Any]) -> ModelResponse:
        for g in self.guardrails:
            response = g.after_model(response, meta)
        return response

    def before_tool(self, tool: str, args: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
        for g in self.guardrails:
            args = g.before_tool(tool, args, meta)
        return args

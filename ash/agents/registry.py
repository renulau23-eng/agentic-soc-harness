"""Adapters and registry.

``FunctionAgent`` wraps any Python callable — the migration path for the
existing v3 / HAL-O agents: wrap, register, and they inherit governance.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ash.agents.base import Agent, RunContext
from ash.core.errors import NotFound
from ash.core.types import AgentResult

AgentFn = Callable[[RunContext, dict[str, Any]], AgentResult | dict[str, Any]]


class FunctionAgent:
    def __init__(
        self,
        *,
        name: str,
        description: str,
        fn: AgentFn,
        allowed_tools: list[str] | None = None,
        tags: list[str] | None = None,
    ):
        self.name = name
        self.description = description
        self.fn = fn
        self.allowed_tools = list(allowed_tools or [])
        self.tags = tags or []

    def run(self, ctx: RunContext, input: dict[str, Any]) -> AgentResult:
        out = self.fn(ctx, input)
        if isinstance(out, AgentResult):
            return out
        if isinstance(out, dict):
            return AgentResult(output=out, summary=str(out.get("summary", "")))
        return AgentResult(output={"value": out}, summary=str(out))


def agent(
    name: str, *, description: str = "", allowed_tools: list[str] | None = None, tags: list[str] | None = None
) -> Callable[[AgentFn], FunctionAgent]:
    def deco(fn: AgentFn) -> FunctionAgent:
        return FunctionAgent(
            name=name,
            description=description or (fn.__doc__ or name).strip(),
            fn=fn,
            allowed_tools=allowed_tools,
            tags=tags,
        )

    return deco


class AgentRegistry:
    def __init__(self) -> None:
        self._agents: dict[str, Agent] = {}

    def register(self, a: Agent, *, replace: bool = False) -> Agent:
        if a.name in self._agents and not replace:
            raise ValueError(f"agent '{a.name}' already registered")
        self._agents[a.name] = a
        return a

    def register_many(self, agents: list[Agent]) -> None:
        for a in agents:
            self.register(a)

    def get(self, name: str) -> Agent:
        try:
            return self._agents[name]
        except KeyError:
            raise NotFound(f"unknown agent '{name}'") from None

    def __contains__(self, name: str) -> bool:
        return name in self._agents

    def names(self) -> list[str]:
        return sorted(self._agents)

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "name": a.name,
                "description": a.description,
                "allowed_tools": list(a.allowed_tools),
                "tags": list(a.tags),
                "kind": type(a).__name__,
            }
            for a in self._agents.values()
        ]

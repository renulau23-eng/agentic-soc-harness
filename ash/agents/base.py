"""Agent contract and run context.

An agent is anything with ``name``, ``allowed_tools`` and ``run(ctx, input)``.
The ``RunContext`` is the agent's only door to the outside world: it calls
models and tools *through the harness*, which is where governance lives.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ash.core.types import AgentResult, Message, ModelResponse, Principal, ToolCall, ToolResult, ToolSpec


class Runtime(Protocol):
    """What the harness exposes to a ``RunContext`` (implemented in ash.runtime)."""

    def chat(
        self, ctx: RunContext, messages: list[Message], tools: list[ToolSpec] | None, profile: str | None
    ) -> ModelResponse: ...

    def call_tool(self, ctx: RunContext, call: ToolCall) -> ToolResult: ...

    def tool_specs(self, names: list[str] | None) -> list[ToolSpec]: ...

    def note(self, ctx: RunContext, text: str, data: dict[str, Any] | None = None) -> None: ...

    def save_state(self, ctx: RunContext) -> None: ...


class RunContext:
    def __init__(
        self,
        *,
        runtime: Runtime,
        run_id: str,
        case_id: str | None,
        trace_id: str,
        principal: Principal,
        agent: str | None,
        state: dict[str, Any],
        root: RunContext | None = None,
        model_profile: str | None = None,
        max_steps: int = 12,
    ):
        self._runtime = runtime
        self.run_id = run_id
        self.case_id = case_id
        self.trace_id = trace_id
        self.principal = principal
        self.agent = agent
        self.state = state  # persisted dict; agents keep resumable state here
        self.root = root or self
        self.model_profile = model_profile
        self.max_steps = max_steps
        # Set by the harness on resume: the human decision for the parked tool call.
        self.pending_tool_result: dict[str, Any] | None = None

    # --- model & tools ------------------------------------------------- #
    def chat(
        self, messages: list[Message], tools: list[ToolSpec] | None = None, profile: str | None = None
    ) -> ModelResponse:
        return self._runtime.chat(self, messages, tools, profile or self.model_profile)

    def call_tool(self, call: ToolCall) -> ToolResult:
        return self._runtime.call_tool(self, call)

    def tool_specs(self, names: list[str] | None) -> list[ToolSpec]:
        return self._runtime.tool_specs(names)

    def note(self, text: str, data: dict[str, Any] | None = None) -> None:
        self._runtime.note(self, text, data)

    def save(self) -> None:
        self._runtime.save_state(self.root)

    # --- resume plumbing ---------------------------------------------- #
    def child(self, *, agent: str, state_key: str, model_profile: str | None = None) -> RunContext:
        """Context for a sub-agent inside a workflow; state nests under ``state_key``."""
        sub_state = self.state.setdefault(state_key, {})
        c = RunContext(
            runtime=self._runtime,
            run_id=self.run_id,
            case_id=self.case_id,
            trace_id=self.trace_id,
            principal=self.principal,
            agent=agent,
            state=sub_state,
            root=self.root,
            model_profile=model_profile or self.model_profile,
            max_steps=self.max_steps,
        )
        return c


@runtime_checkable
class Agent(Protocol):
    name: str
    description: str
    allowed_tools: list[str]  # explicit allow-list; empty list = no tools
    tags: list[str]

    def run(self, ctx: RunContext, input: dict[str, Any]) -> AgentResult: ...

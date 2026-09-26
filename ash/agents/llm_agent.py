"""Reference LLM agent: system prompt + bounded tool-calling loop.

Resumable: the message transcript lives in ``ctx.state["messages"]`` so a
run parked on a human approval continues exactly where it stopped, with the
approved (or rejected) tool result injected as the next message.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ash.agents.base import RunContext
from ash.core.errors import HarnessError
from ash.core.types import AgentResult, CaseStatus, Message, Role, Severity, ToolCall, ToolResult

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)

DEFAULT_OUTPUT_CONTRACT = (
    "When you have finished, reply with a single JSON object and nothing else. "
    "Fields: summary (string), and any task-specific fields. Optional: severity "
    "(info|low|medium|high|critical), confidence (0-1), next_status "
    "(new|triaged|investigating|awaiting_approval|contained|resolved|closed|false_positive)."
)


class LLMAgent:
    def __init__(
        self,
        *,
        name: str,
        description: str,
        system_prompt: str,
        allowed_tools: list[str],
        tags: list[str] | None = None,
        model_profile: str | None = None,
        max_steps: int | None = None,
        output_contract: str = DEFAULT_OUTPUT_CONTRACT,
    ):
        self.name = name
        self.description = description
        self.system_prompt = system_prompt
        self.allowed_tools = list(allowed_tools)
        self.tags = tags or []
        self.model_profile = model_profile
        self.max_steps = max_steps
        self.output_contract = output_contract

    # ------------------------------------------------------------------ #
    def initial_messages(self, input: dict[str, Any]) -> list[Message]:
        return [
            Message(role=Role.SYSTEM, content=f"{self.system_prompt.strip()}\n\n{self.output_contract}"),
            Message(role=Role.USER, content=json.dumps(input, default=str)),
        ]

    def run(self, ctx: RunContext, input: dict[str, Any]) -> AgentResult:
        max_steps = self.max_steps or ctx.max_steps
        tools = ctx.tool_specs(self.allowed_tools) if self.allowed_tools else None

        raw = ctx.state.get("messages")
        messages = [Message(**m) for m in raw] if raw else self.initial_messages(input)
        steps = int(ctx.state.get("steps", 0))

        # Resume path: settle any tool calls still outstanding on the last assistant turn.
        self._settle_outstanding(ctx, messages)

        while steps < max_steps:
            steps += 1
            ctx.state["steps"] = steps
            response = ctx.chat(messages, tools, profile=self.model_profile)
            messages.append(response.as_message())
            self._persist(ctx, messages)

            if not response.wants_tools:
                return self.parse_final(response.content or "")

            for call in response.tool_calls:
                result = ctx.call_tool(call)  # may raise ApprovalRequired (state already persisted)
                messages.append(_tool_message(call, result))
                self._persist(ctx, messages)

        raise HarnessError(f"agent '{self.name}' exceeded step budget ({max_steps}) without a final answer")

    # ------------------------------------------------------------------ #
    def _settle_outstanding(self, ctx: RunContext, messages: list[Message]) -> None:
        """On resume, answer tool calls from the last assistant turn that have no
        tool message yet. The harness serves the approved/rejected result for
        the call that was parked; any others execute normally."""
        last_assistant = next((m for m in reversed(messages) if m.role == Role.ASSISTANT), None)
        if not last_assistant or not last_assistant.tool_calls:
            return
        answered = {m.tool_call_id for m in messages if m.role == Role.TOOL}
        for call in last_assistant.tool_calls:
            if call.id in answered:
                continue
            result = ctx.call_tool(call)
            messages.append(_tool_message(call, result))
            self._persist(ctx, messages)

    def _persist(self, ctx: RunContext, messages: list[Message]) -> None:
        ctx.state["messages"] = [m.model_dump(mode="json") for m in messages]
        ctx.save()

    def parse_final(self, content: str) -> AgentResult:
        text = content.strip()
        m = _FENCE_RE.search(text)
        if m:
            text = m.group(1).strip()
        data: dict[str, Any]
        try:
            parsed = json.loads(text)
            data = parsed if isinstance(parsed, dict) else {"value": parsed}
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            if start != -1 and end > start:
                try:
                    data = json.loads(text[start : end + 1])
                except json.JSONDecodeError:
                    data = {"summary": text}
            else:
                data = {"summary": text}
        return AgentResult(
            output=data,
            summary=str(data.get("summary", ""))[:2000],
            confidence=_maybe_float(data.get("confidence")),
            severity=_maybe_enum(Severity, data.get("severity")),
            next_status=_maybe_enum(CaseStatus, data.get("next_status")),
        )


def _tool_message(call: ToolCall, result: ToolResult) -> Message:
    return Message(role=Role.TOOL, tool_call_id=call.id, name=call.name, content=result.to_content())


def _maybe_float(v: Any) -> float | None:
    try:
        return None if v is None else float(v)
    except (TypeError, ValueError):
        return None


def _maybe_enum(enum_cls: Any, v: Any) -> Any:
    if v is None:
        return None
    try:
        return enum_cls(str(v).lower())
    except ValueError:
        return None

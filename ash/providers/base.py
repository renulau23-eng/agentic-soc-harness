"""Model provider contract.

Every provider — Nemotron over NIM, vLLM, a sovereign model, a mock — implements
the same ``chat`` signature. Agents never see a vendor SDK.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ash.core.types import Message, ModelResponse, ToolSpec


@runtime_checkable
class ModelProvider(Protocol):
    name: str
    model: str

    def chat(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> ModelResponse:
        """Return the model's next turn. Must populate ``tool_calls`` when the
        model wants tools, and ``content`` for a final answer."""
        ...

    def healthcheck(self) -> bool: ...

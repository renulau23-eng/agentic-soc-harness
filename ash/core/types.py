"""Core data contracts shared across the harness.

Everything here is a plain Pydantic model so it can be serialised to the
database, logged, and returned from the API without translation layers.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def utcnow() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- #
# Model I/O
# --------------------------------------------------------------------------- #


class Role(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ToolCall(BaseModel):
    """A model's request to invoke a tool (OpenAI-compatible shape)."""

    id: str = Field(default_factory=lambda: new_id("call"))
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class Message(BaseModel):
    role: Role
    content: str | None = None
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None

    def to_openai(self) -> dict[str, Any]:
        msg: dict[str, Any] = {"role": self.role.value, "content": self.content or ""}
        if self.tool_calls:
            msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.name, "arguments": _json_dumps(tc.arguments)},
                }
                for tc in self.tool_calls
            ]
        if self.tool_call_id:
            msg["tool_call_id"] = self.tool_call_id
        if self.name:
            msg["name"] = self.name
        return msg


class Usage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ModelResponse(BaseModel):
    content: str | None = None
    tool_calls: list[ToolCall] = Field(default_factory=list)
    reasoning: str | None = None
    usage: Usage = Field(default_factory=Usage)
    model: str = ""
    provider: str = ""
    latency_ms: float = 0.0
    finish_reason: str | None = None

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)

    def as_message(self) -> Message:
        return Message(role=Role.ASSISTANT, content=self.content, tool_calls=self.tool_calls)


# --------------------------------------------------------------------------- #
# Tools & governance
# --------------------------------------------------------------------------- #


class RiskTier(StrEnum):
    LOW = "low"  # read-only lookups
    MEDIUM = "medium"  # writes with low blast radius (notes, tickets)
    HIGH = "high"  # containment / blocking — reversible but impactful
    CRITICAL = "critical"  # irreversible or wide blast radius

    @property
    def rank(self) -> int:
        return ["low", "medium", "high", "critical"].index(self.value)


class PolicyDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class PolicyResult(BaseModel):
    decision: PolicyDecision
    reason: str
    rule: str | None = None


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ToolSpec(BaseModel):
    """Serialisable description of a tool (what the API and models see)."""

    name: str
    description: str
    parameters: dict[str, Any]
    risk_tier: RiskTier
    permission: str
    tags: list[str] = Field(default_factory=list)

    def to_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


class ToolResult(BaseModel):
    tool: str
    call_id: str
    ok: bool
    result: Any = None
    error: str | None = None
    duration_ms: float = 0.0
    approval_id: str | None = None

    def to_content(self) -> str:
        payload = {"ok": self.ok, "result": self.result} if self.ok else {"ok": False, "error": self.error}
        return _json_dumps(payload)


# --------------------------------------------------------------------------- #
# Cases, runs, alerts
# --------------------------------------------------------------------------- #


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class CaseStatus(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepType(StrEnum):
    MODEL = "model"
    TOOL = "tool"
    APPROVAL = "approval"
    NOTE = "note"
    STAGE = "stage"


class AlertIn(BaseModel):
    source: str
    title: str
    severity: Severity = Severity.MEDIUM
    description: str = ""
    indicators: list[str] = Field(default_factory=list)
    asset_id: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    case_id: str | None = None


class AgentResult(BaseModel):
    """What an agent hands back to the harness."""

    output: dict[str, Any] = Field(default_factory=dict)
    summary: str = ""
    confidence: float | None = None
    severity: Severity | None = None
    next_status: CaseStatus | None = None


class Principal(BaseModel):
    id: str
    name: str
    kind: str = "user"  # user | service | agent
    roles: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, default=str, separators=(",", ":"), sort_keys=True)

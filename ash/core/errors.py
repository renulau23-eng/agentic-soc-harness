"""Harness-wide exception hierarchy."""

from __future__ import annotations


class HarnessError(Exception):
    """Base class for all harness errors."""


class ConfigurationError(HarnessError):
    pass


class AuthenticationError(HarnessError):
    pass


class AuthorizationError(HarnessError):
    pass


class PolicyDeniedError(HarnessError):
    def __init__(self, tool: str, reason: str):
        super().__init__(f"tool '{tool}' denied by policy: {reason}")
        self.tool = tool
        self.reason = reason


class ApprovalRequired(HarnessError):
    """Raised inside a run when a tool call needs a human decision.

    The runtime catches it, persists run state, and parks the run in
    ``AWAITING_APPROVAL``. It is a control-flow signal, not a failure.
    """

    def __init__(self, approval_id: str, tool: str, call_id: str):
        super().__init__(f"approval required for tool '{tool}' (approval {approval_id})")
        self.approval_id = approval_id
        self.tool = tool
        self.call_id = call_id


class ToolExecutionError(HarnessError):
    pass


class ToolValidationError(ToolExecutionError):
    pass


class ProviderError(HarnessError):
    pass


class GuardrailBlocked(HarnessError):
    def __init__(self, stage: str, reason: str):
        super().__init__(f"blocked by guardrail at {stage}: {reason}")
        self.stage = stage
        self.reason = reason


class NotFound(HarnessError):
    pass


class RateLimited(HarnessError):
    pass

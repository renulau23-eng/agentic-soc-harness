"""Policy engine: decides allow / deny / require_approval for every tool call.

Evaluation order (first match wins):
1. Explicit rules from policy YAML (ordered). A rule may deny anything or
   auto-approve for a role, but an ALLOW never exceeds what RBAC grants.
2. RBAC: if the principal lacks the tool's permission, the call is escalated
   to human approval (default) or denied (``escalate_on_missing_permission``).
3. Tier defaults: LOW/MEDIUM allow, HIGH/CRITICAL require approval.

Rule fields (all optional, all must match): ``tools``, ``tiers``, ``agents``,
``roles`` (any of principal's roles), ``min_tier``; ``decision`` is required.
"""

from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

import yaml
from pydantic import BaseModel, Field

from ash.core.types import PolicyDecision, PolicyResult, Principal, RiskTier
from ash.governance.rbac import RBAC
from ash.tools.base import Tool


class PolicyRule(BaseModel):
    name: str
    decision: PolicyDecision
    reason: str = ""
    tools: list[str] = Field(default_factory=list)  # glob patterns
    tiers: list[RiskTier] = Field(default_factory=list)
    min_tier: RiskTier | None = None
    agents: list[str] = Field(default_factory=list)  # glob patterns
    roles: list[str] = Field(default_factory=list)

    def matches(self, tool: Tool, agent: str | None, principal: Principal) -> bool:
        if self.tools and not any(fnmatch(tool.name, p) for p in self.tools):
            return False
        if self.tiers and tool.risk_tier not in self.tiers:
            return False
        if self.min_tier and tool.risk_tier.rank < self.min_tier.rank:
            return False
        if self.agents and not any(fnmatch(agent or "", p) for p in self.agents):
            return False
        if self.roles and not (set(self.roles) & set(principal.roles)):
            return False
        return True


class PolicyConfig(BaseModel):
    rules: list[PolicyRule] = Field(default_factory=list)
    tier_defaults: dict[RiskTier, PolicyDecision] = Field(
        default_factory=lambda: {
            RiskTier.LOW: PolicyDecision.ALLOW,
            RiskTier.MEDIUM: PolicyDecision.ALLOW,
            RiskTier.HIGH: PolicyDecision.REQUIRE_APPROVAL,
            RiskTier.CRITICAL: PolicyDecision.REQUIRE_APPROVAL,
        }
    )
    roles: dict[str, list[str]] = Field(default_factory=dict)  # extra/override RBAC roles
    # When the run's principal lacks the tool's permission: escalate to a human
    # who has it (True — the agent proposes, an authorised human disposes) or deny.
    escalate_on_missing_permission: bool = True

    @classmethod
    def from_yaml(cls, path: str) -> PolicyConfig:
        with open(path, encoding="utf-8") as fh:
            data: dict[str, Any] = yaml.safe_load(fh) or {}
        return cls(**data)


class PolicyEngine:
    def __init__(self, rbac: RBAC, config: PolicyConfig | None = None):
        self.rbac = rbac
        self.config = config or PolicyConfig()
        for role, perms in self.config.roles.items():
            self.rbac.add_role(role, set(perms))

    def evaluate(self, tool: Tool, principal: Principal, agent: str | None = None) -> PolicyResult:
        # 1. explicit rules always win (they can deny anything, or auto-approve for a role)
        for rule in self.config.rules:
            if rule.matches(tool, agent, principal):
                if rule.decision == PolicyDecision.ALLOW and not self.rbac.has(principal, tool.permission):
                    # a rule cannot grant more than RBAC allows
                    return self._missing_permission(tool, rule.name)
                return PolicyResult(
                    decision=rule.decision, rule=rule.name, reason=rule.reason or f"matched rule '{rule.name}'"
                )
        # 2. RBAC gate
        if not self.rbac.has(principal, tool.permission):
            return self._missing_permission(tool, "rbac")
        # 3. tier default
        default = self.config.tier_defaults.get(tool.risk_tier, PolicyDecision.REQUIRE_APPROVAL)
        return PolicyResult(decision=default, rule="tier_default", reason=f"tier default for {tool.risk_tier.value}")

    def _missing_permission(self, tool: Tool, rule: str) -> PolicyResult:
        if self.config.escalate_on_missing_permission:
            return PolicyResult(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                rule=f"{rule}:escalate",
                reason=f"principal lacks '{tool.permission}'; escalated to an authorised approver",
            )
        return PolicyResult(decision=PolicyDecision.DENY, rule=rule, reason=f"principal lacks '{tool.permission}'")

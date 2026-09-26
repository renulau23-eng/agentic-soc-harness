"""Role-based access control.

Permissions are dotted strings. A role maps to a set of permissions; ``*``
and prefix wildcards (``tools:execute:*``) are supported. Roles can be
extended or overridden from the policy YAML.
"""

from __future__ import annotations

from fnmatch import fnmatch

from ash.core.errors import AuthorizationError
from ash.core.types import Principal, RiskTier

# Canonical permissions ------------------------------------------------------
P_AGENTS_READ = "agents:read"
P_AGENTS_RUN = "agents:run"
P_TOOLS_READ = "tools:read"
P_TOOLS_EXEC = "tools:execute"  # + ":low|medium|high|critical"
P_CASES_READ = "cases:read"
P_CASES_WRITE = "cases:write"
P_ALERTS_INGEST = "alerts:ingest"
P_APPROVALS_READ = "approvals:read"
P_APPROVALS_DECIDE = "approvals:decide"
P_AUDIT_READ = "audit:read"
P_AUDIT_VERIFY = "audit:verify"
P_ADMIN = "admin:*"

DEFAULT_ROLES: dict[str, set[str]] = {
    "viewer": {P_AGENTS_READ, P_TOOLS_READ, P_CASES_READ, P_APPROVALS_READ},
    "analyst": {
        P_AGENTS_READ,
        P_AGENTS_RUN,
        P_TOOLS_READ,
        P_CASES_READ,
        P_CASES_WRITE,
        P_ALERTS_INGEST,
        P_APPROVALS_READ,
        "tools:execute:low",
        "tools:execute:medium",
    },
    "senior_analyst": {
        P_AGENTS_READ,
        P_AGENTS_RUN,
        P_TOOLS_READ,
        P_CASES_READ,
        P_CASES_WRITE,
        P_ALERTS_INGEST,
        P_APPROVALS_READ,
        P_APPROVALS_DECIDE,
        "tools:execute:low",
        "tools:execute:medium",
        "tools:execute:high",
    },
    "soc_lead": {
        P_AGENTS_READ,
        P_AGENTS_RUN,
        P_TOOLS_READ,
        P_CASES_READ,
        P_CASES_WRITE,
        P_ALERTS_INGEST,
        P_APPROVALS_READ,
        P_APPROVALS_DECIDE,
        "tools:execute:*",
        P_AUDIT_READ,
    },
    "agent_engineer": {
        P_AGENTS_READ,
        P_AGENTS_RUN,
        P_TOOLS_READ,
        P_CASES_READ,
        P_CASES_WRITE,
        P_ALERTS_INGEST,
        "tools:execute:low",
        "tools:execute:medium",
    },
    "auditor": {P_AGENTS_READ, P_TOOLS_READ, P_CASES_READ, P_APPROVALS_READ, P_AUDIT_READ, P_AUDIT_VERIFY},
    "service": {
        P_ALERTS_INGEST,
        P_AGENTS_RUN,
        P_CASES_READ,
        P_CASES_WRITE,
        "tools:execute:low",
        "tools:execute:medium",
    },
    "admin": {P_ADMIN},
}


class RBAC:
    def __init__(self, roles: dict[str, set[str]] | None = None):
        self._roles: dict[str, set[str]] = {k: set(v) for k, v in (roles or DEFAULT_ROLES).items()}

    def add_role(self, name: str, permissions: set[str]) -> None:
        self._roles[name] = set(permissions)

    def roles(self) -> dict[str, set[str]]:
        return {k: set(v) for k, v in self._roles.items()}

    def permissions_for(self, principal: Principal) -> set[str]:
        perms: set[str] = set()
        for r in principal.roles:
            perms |= self._roles.get(r, set())
        return perms

    def has(self, principal: Principal, permission: str) -> bool:
        perms = self.permissions_for(principal)
        if P_ADMIN in perms:
            return True
        for p in perms:
            if p == permission or fnmatch(permission, p):
                return True
        return False

    def require(self, principal: Principal, permission: str) -> None:
        if not self.has(principal, permission):
            raise AuthorizationError(f"principal '{principal.id}' lacks permission '{permission}'")

    def can_execute_tier(self, principal: Principal, tier: RiskTier) -> bool:
        return self.has(principal, f"{P_TOOLS_EXEC}:{tier.value}")

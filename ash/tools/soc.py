"""Reference SOC tool pack. Each tool declares its risk tier; the policy
engine decides whether it runs, is denied, or waits for a human."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ash.connectors.base import Connectors
from ash.core.types import Principal, RiskTier
from ash.tools.base import Tool, tool


@dataclass
class ToolContext:
    connectors: Connectors
    principal: Principal
    case_id: str | None
    run_id: str | None
    agent: str | None


# ---- LOW: read-only enrichment -------------------------------------------- #


@tool(risk_tier=RiskTier.LOW, tags=["siem", "enrichment"])
def search_siem(ctx: ToolContext, query: str, hours: int = 24, limit: int = 100) -> dict[str, Any]:
    """Search the SIEM / data lake for events matching a query (e.g. 'indicator:1.2.3.4', 'host:X')."""
    return ctx.connectors.siem.search(query=query, hours=hours, limit=limit)


@tool(risk_tier=RiskTier.LOW, tags=["ti", "enrichment"])
def lookup_ioc(ctx: ToolContext, indicator: str) -> dict[str, Any]:
    """Look up an indicator (IP, domain, hash) in threat intelligence."""
    return ctx.connectors.ti.lookup(indicator)


@tool(risk_tier=RiskTier.LOW, tags=["assets", "platform"])
def get_asset(ctx: ToolContext, asset_id: str) -> dict[str, Any]:
    """Fetch an asset record from the asset inventory (owner, criticality, tags)."""
    return ctx.connectors.assets.get_asset(asset_id)


@tool(risk_tier=RiskTier.LOW, tags=["crvm", "platform"])
def get_vulnerabilities(ctx: ToolContext, asset_id: str) -> dict[str, Any]:
    """Fetch open vulnerabilities for an asset from CRVM."""
    return ctx.connectors.vulns.get_vulnerabilities(asset_id)


@tool(risk_tier=RiskTier.LOW, tags=["edr"])
def get_host_status(ctx: ToolContext, host_id: str) -> dict[str, Any]:
    """Return EDR status (isolated or not) for a host."""
    return ctx.connectors.edr.get_host(host_id)


# ---- MEDIUM: low-blast-radius writes ------------------------------------- #


@tool(risk_tier=RiskTier.MEDIUM, tags=["ticketing"])
def create_ticket(ctx: ToolContext, title: str, description: str, priority: str = "P3") -> dict[str, Any]:
    """Create an incident ticket in the ticketing system."""
    return ctx.connectors.ticketing.create(title=title, description=description, priority=priority)


@tool(risk_tier=RiskTier.MEDIUM, tags=["remediation", "platform"])
def request_remediation(ctx: ToolContext, asset_id: str, finding: str, priority: str = "P2") -> dict[str, Any]:
    """Hand a finding to Remediation OS for tracked remediation."""
    return ctx.connectors.remediation.request_remediation(asset_id=asset_id, finding=finding, priority=priority)


# ---- HIGH: containment (human approval by default) ----------------------- #


@tool(risk_tier=RiskTier.HIGH, tags=["edr", "containment"])
def isolate_host(ctx: ToolContext, host_id: str, reason: str) -> dict[str, Any]:
    """Network-isolate a host via EDR. Reversible but disruptive."""
    return ctx.connectors.edr.isolate_host(host_id=host_id, reason=reason)


@tool(risk_tier=RiskTier.HIGH, tags=["network", "containment"])
def block_indicator(ctx: ToolContext, indicator: str, scope: str = "perimeter") -> dict[str, Any]:
    """Block an indicator (IP/domain) at the perimeter or on endpoints."""
    return ctx.connectors.network.block_indicator(indicator=indicator, scope=scope)


# ---- CRITICAL: irreversible ---------------------------------------------- #


@tool(risk_tier=RiskTier.CRITICAL, tags=["edr", "containment"])
def release_host(ctx: ToolContext, host_id: str, reason: str) -> dict[str, Any]:
    """Release a host from isolation. Critical because it re-exposes a possibly compromised asset."""
    return ctx.connectors.edr.release_host(host_id=host_id, reason=reason)


def soc_tools() -> list[Tool]:
    return [
        search_siem,
        lookup_ioc,
        get_asset,
        get_vulnerabilities,
        get_host_status,
        create_ticket,
        request_remediation,
        isolate_host,
        block_indicator,
        release_host,
    ]

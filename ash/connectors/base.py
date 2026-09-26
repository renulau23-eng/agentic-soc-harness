"""Connector protocols.

Connectors are the harness's edges to the rest of the estate: SIEM, EDR,
threat intel, ticketing, and the CoE full-stack platform (asset inventory,
CRVM vulnerability data, Remediation OS). Tools call connectors; connectors
never call models. Client-specific implementations are delivered per
engagement and selected by configuration.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SIEMConnector(Protocol):
    def search(self, query: str, hours: int = 24, limit: int = 100) -> dict[str, Any]: ...


@runtime_checkable
class EDRConnector(Protocol):
    def isolate_host(self, host_id: str, reason: str) -> dict[str, Any]: ...
    def release_host(self, host_id: str, reason: str) -> dict[str, Any]: ...
    def get_host(self, host_id: str) -> dict[str, Any]: ...


@runtime_checkable
class ThreatIntelConnector(Protocol):
    def lookup(self, indicator: str) -> dict[str, Any]: ...


@runtime_checkable
class TicketingConnector(Protocol):
    def create(self, title: str, description: str, priority: str) -> dict[str, Any]: ...


@runtime_checkable
class AssetConnector(Protocol):
    """Asset inventory / inventory insights layer of the full-stack platform."""

    def get_asset(self, asset_id: str) -> dict[str, Any]: ...


@runtime_checkable
class VulnerabilityConnector(Protocol):
    """CRVM (cyber risk & vulnerability management) layer."""

    def get_vulnerabilities(self, asset_id: str) -> dict[str, Any]: ...


@runtime_checkable
class RemediationConnector(Protocol):
    """Remediation OS hand-off."""

    def request_remediation(self, asset_id: str, finding: str, priority: str) -> dict[str, Any]: ...


@runtime_checkable
class NetworkConnector(Protocol):
    def block_indicator(self, indicator: str, scope: str) -> dict[str, Any]: ...


class Connectors:
    """Bag of connectors handed to tools via ``ToolContext``."""

    def __init__(
        self,
        *,
        siem: SIEMConnector,
        edr: EDRConnector,
        ti: ThreatIntelConnector,
        ticketing: TicketingConnector,
        assets: AssetConnector,
        vulns: VulnerabilityConnector,
        remediation: RemediationConnector,
        network: NetworkConnector,
    ):
        self.siem = siem
        self.edr = edr
        self.ti = ti
        self.ticketing = ticketing
        self.assets = assets
        self.vulns = vulns
        self.remediation = remediation
        self.network = network

"""In-memory reference connectors.

They behave like real systems (stateful, deterministic) so tools, policies
and workflows can be exercised end to end without any external service.
Seed data represents a small enterprise estate with one compromised host.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any

from ash.connectors.base import Connectors
from ash.core.types import new_id

_MALICIOUS_IOCS = {
    "185.220.101.45": {"malicious": True, "confidence": 0.97, "tags": ["c2", "cobalt-strike"], "source": "coe-ti"},
    "evil-updates.xyz": {"malicious": True, "confidence": 0.93, "tags": ["c2", "dns"], "source": "coe-ti"},
    "44d88612fea8a8f36de82e1278abb02f": {
        "malicious": True,
        "confidence": 0.99,
        "tags": ["eicar-test"],
        "source": "coe-ti",
    },
}

_ASSETS = {
    "host-fin-042": {
        "asset_id": "host-fin-042",
        "hostname": "FIN-WS-042",
        "owner": "finance",
        "criticality": "high",
        "os": "Windows 11",
        "ip": "10.20.4.42",
        "tags": ["pci", "finance"],
    },
    "host-dev-007": {
        "asset_id": "host-dev-007",
        "hostname": "DEV-LX-007",
        "owner": "engineering",
        "criticality": "medium",
        "os": "Ubuntu 24.04",
        "ip": "10.30.1.7",
        "tags": ["dev"],
    },
}

_VULNS = {
    "host-fin-042": [
        {"cve": "CVE-2025-21298", "cvss": 9.8, "exploited": True, "component": "Windows OLE"},
        {"cve": "CVE-2024-38063", "cvss": 9.8, "exploited": False, "component": "Windows TCP/IP"},
    ],
    "host-dev-007": [{"cve": "CVE-2024-6387", "cvss": 8.1, "exploited": True, "component": "OpenSSH"}],
}

_EVENTS = [
    {"ts": "2026-09-26T17:02:11Z", "host": "host-fin-042", "event": "dns_query", "dst": "evil-updates.xyz"},
    {"ts": "2026-09-26T17:02:12Z", "host": "host-fin-042", "event": "net_conn", "dst": "185.220.101.45:443"},
    {"ts": "2026-09-26T17:05:40Z", "host": "host-fin-042", "event": "net_conn", "dst": "185.220.101.45:443"},
    {
        "ts": "2026-09-26T17:09:03Z",
        "host": "host-fin-042",
        "event": "process",
        "image": "powershell.exe",
        "cmd": "-enc ...",
    },
]


class MemorySIEM:
    def search(self, query: str, hours: int = 24, limit: int = 100) -> dict[str, Any]:
        q = query.replace("indicator:", "").replace("host:", "").strip().lower()
        hits = [e for e in _EVENTS if q == "*" or q in str(e).lower()][:limit]
        return {"query": query, "hours": hours, "count": len(hits), "events": hits}


class MemoryEDR:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.isolated: dict[str, dict[str, Any]] = {}

    def isolate_host(self, host_id: str, reason: str) -> dict[str, Any]:
        with self._lock:
            self.isolated[host_id] = {"reason": reason, "at": datetime.now(UTC).isoformat()}
        return {"host_id": host_id, "isolated": True, "reason": reason}

    def release_host(self, host_id: str, reason: str) -> dict[str, Any]:
        with self._lock:
            self.isolated.pop(host_id, None)
        return {"host_id": host_id, "isolated": False, "reason": reason}

    def get_host(self, host_id: str) -> dict[str, Any]:
        return {"host_id": host_id, "isolated": host_id in self.isolated}


class MemoryThreatIntel:
    def lookup(self, indicator: str) -> dict[str, Any]:
        info = _MALICIOUS_IOCS.get(indicator.lower())
        return {
            "indicator": indicator,
            **(info or {"malicious": False, "confidence": 0.1, "tags": [], "source": "coe-ti"}),
        }


class MemoryTicketing:
    def __init__(self) -> None:
        self.tickets: list[dict[str, Any]] = []

    def create(self, title: str, description: str, priority: str) -> dict[str, Any]:
        t = {
            "ticket_id": new_id("tkt"),
            "title": title,
            "description": description,
            "priority": priority,
            "status": "open",
        }
        self.tickets.append(t)
        return t


class MemoryAssets:
    def get_asset(self, asset_id: str) -> dict[str, Any]:
        return dict(_ASSETS.get(asset_id) or {"asset_id": asset_id, "criticality": "unknown", "found": False})


class MemoryVulns:
    def get_vulnerabilities(self, asset_id: str) -> dict[str, Any]:
        items = _VULNS.get(asset_id, [])
        return {"asset_id": asset_id, "count": len(items), "items": items}


class MemoryRemediation:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def request_remediation(self, asset_id: str, finding: str, priority: str) -> dict[str, Any]:
        r = {
            "remediation_id": new_id("rem"),
            "asset_id": asset_id,
            "finding": finding,
            "priority": priority,
            "status": "queued",
        }
        self.requests.append(r)
        return r


class MemoryNetwork:
    def __init__(self) -> None:
        self.blocked: list[dict[str, Any]] = []

    def block_indicator(self, indicator: str, scope: str) -> dict[str, Any]:
        entry = {"indicator": indicator, "scope": scope, "rule_id": new_id("fw")}
        self.blocked.append(entry)
        return {**entry, "blocked": True}


def memory_connectors() -> Connectors:
    return Connectors(
        siem=MemorySIEM(),
        edr=MemoryEDR(),
        ti=MemoryThreatIntel(),
        ticketing=MemoryTicketing(),
        assets=MemoryAssets(),
        vulns=MemoryVulns(),
        remediation=MemoryRemediation(),
        network=MemoryNetwork(),
    )

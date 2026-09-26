"""Offline, deterministic providers for CI, air-gapped smoke tests and demos.

``MockProvider`` replays a script or delegates to a responder function.
``SOCPlaybookProvider`` is a rule-based stand-in for a SOC-tuned model: it
drives the reference triage → investigate → respond workflow through real
tool calls with no GPU, which lets the *harness* be tested end to end
independently of model quality.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from ash.core.errors import ProviderError
from ash.core.types import Message, ModelResponse, Role, ToolCall, ToolSpec, Usage

Responder = Callable[[list[Message], list[ToolSpec] | None, dict[str, Any]], ModelResponse]


class MockProvider:
    name = "mock"

    def __init__(
        self,
        script: list[ModelResponse | dict[str, Any]] | None = None,
        responder: Responder | None = None,
        model: str = "mock",
    ):
        self.model = model
        self._script = [r if isinstance(r, ModelResponse) else ModelResponse(**r) for r in (script or [])]
        self._responder = responder
        self.calls: list[dict[str, Any]] = []

    def chat(
        self, messages: list[Message], tools: list[ToolSpec] | None = None, *, metadata: dict[str, Any] | None = None
    ) -> ModelResponse:
        self.calls.append(
            {
                "messages": [m.model_dump() for m in messages],
                "tools": [t.name for t in tools or []],
                "metadata": metadata or {},
            }
        )
        if self._script:
            resp = self._script.pop(0)
        elif self._responder:
            resp = self._responder(messages, tools, metadata or {})
        else:
            resp = ModelResponse(content=json.dumps({"summary": "mock response", "output": {}}))
        resp.provider = self.name
        resp.model = self.model
        resp.usage = resp.usage or Usage()
        return resp

    def healthcheck(self) -> bool:
        return True


# --------------------------------------------------------------------------- #
# SOC playbook responder
# --------------------------------------------------------------------------- #

_IOC_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-f0-9]{32,64}\b|\b[\w.-]+\.(?:com|net|org|io|ru|cn|xyz)\b", re.I)


def _tool_names_called(messages: list[Message]) -> list[str]:
    names: list[str] = []
    for m in messages:
        for tc in m.tool_calls:
            names.append(tc.name)
    return names


def _last_user_json(messages: list[Message]) -> dict[str, Any]:
    for m in reversed(messages):
        if m.role == Role.USER and m.content:
            try:
                return json.loads(m.content)
            except json.JSONDecodeError:
                return {"text": m.content}
    return {}


def _tool_results(messages: list[Message]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for m in messages:
        if m.role == Role.TOOL and m.name and m.content:
            try:
                out[m.name] = json.loads(m.content)
            except json.JSONDecodeError:
                out[m.name] = m.content
    return out


def _final(payload: dict[str, Any]) -> ModelResponse:
    return ModelResponse(content=json.dumps(payload), finish_reason="stop")


def _call(name: str, **args: Any) -> ModelResponse:
    return ModelResponse(tool_calls=[ToolCall(name=name, arguments=args)], finish_reason="tool_calls")


def soc_playbook(messages: list[Message], tools: list[ToolSpec] | None, metadata: dict[str, Any]) -> ModelResponse:
    """A deterministic 'model' that behaves like a competent SOC analyst."""
    available = {t.name for t in tools or []}
    called = _tool_names_called(messages)
    inp = _last_user_json(messages)
    results = _tool_results(messages)
    agent = (metadata.get("agent") or "").lower()

    alert = inp.get("alert", inp)
    indicators: list[str] = list(alert.get("indicators") or [])
    if not indicators:
        indicators = _IOC_RE.findall(json.dumps(alert))[:3]
    asset_id = alert.get("asset_id") or inp.get("asset_id")

    # ---------------- triage ----------------
    if "triage" in agent:
        if "lookup_ioc" in available and indicators and "lookup_ioc" not in called:
            return _call("lookup_ioc", indicator=indicators[0])
        ti = results.get("lookup_ioc", {}).get("result", {})
        malicious = bool(ti.get("malicious"))
        sev = "high" if malicious else "low"
        return _final(
            {
                "verdict": "true_positive" if malicious else "benign",
                "severity": sev,
                "confidence": 0.92 if malicious else 0.7,
                "summary": f"Indicator {indicators[0] if indicators else 'n/a'} "
                f"{'is flagged malicious by threat intel' if malicious else 'has no malicious reputation'}.",
                "next_status": "triaged" if malicious else "false_positive",
            }
        )

    # ---------------- investigate ----------------
    if "investigat" in agent:
        if "search_siem" in available and "search_siem" not in called:
            q = f"indicator:{indicators[0]}" if indicators else "*"
            return _call("search_siem", query=q, hours=24)
        if asset_id and "get_asset" in available and "get_asset" not in called:
            return _call("get_asset", asset_id=asset_id)
        if asset_id and "get_vulnerabilities" in available and "get_vulnerabilities" not in called:
            return _call("get_vulnerabilities", asset_id=asset_id)
        siem = results.get("search_siem", {}).get("result", {})
        asset = results.get("get_asset", {}).get("result", {})
        vulns = results.get("get_vulnerabilities", {}).get("result", {})
        hits = siem.get("count", 0)
        crit = asset.get("criticality", "unknown")
        return _final(
            {
                "attack_chain": ["initial_access", "c2_beacon"] if hits else [],
                "affected_assets": [asset_id] if asset_id else [],
                "siem_hits": hits,
                "asset_criticality": crit,
                "exploitable_vulns": [v.get("cve") for v in vulns.get("items", []) if v.get("exploited")],
                "recommended_actions": ["isolate_host", "block_indicator", "create_ticket"] if hits else ["monitor"],
                "severity": "critical" if (hits and crit == "high") else ("high" if hits else "medium"),
                "summary": f"{hits} correlated SIEM events; asset criticality {crit}.",
                "next_status": "investigating",
            }
        )

    # ---------------- respond ----------------
    if "respon" in agent:
        if asset_id and "isolate_host" in available and "isolate_host" not in called:
            return _call("isolate_host", host_id=asset_id, reason="Confirmed C2 beaconing")
        if indicators and "block_indicator" in available and "block_indicator" not in called:
            return _call("block_indicator", indicator=indicators[0], scope="perimeter")
        if "create_ticket" in available and "create_ticket" not in called:
            return _call(
                "create_ticket",
                title=f"IR: {alert.get('title', 'incident')}",
                priority="P1",
                description="Containment executed by agentic SOC; human approval on record.",
            )
        iso = results.get("isolate_host", {})
        actions = {
            k: v.get("ok") for k, v in results.items() if k in {"isolate_host", "block_indicator", "create_ticket"}
        }
        contained = bool(iso.get("ok"))
        return _final(
            {
                "actions": actions,
                "contained": contained,
                "summary": "Host isolated, indicator blocked and IR ticket raised."
                if contained
                else "Containment not executed (rejected or unavailable); ticket raised for manual follow-up.",
                "next_status": "contained" if contained else "investigating",
            }
        )

    # ---------------- generic fallback ----------------
    if tools and not called:
        first = next(iter(tools))
        return _call(first.name, **_sample_args(first))
    return _final({"summary": "completed", "output": results})


def _sample_args(tool: ToolSpec) -> dict[str, Any]:
    props = tool.parameters.get("properties", {})
    out: dict[str, Any] = {}
    for k, spec in props.items():
        if k not in tool.parameters.get("required", []):
            continue
        t = spec.get("type")
        out[k] = {"integer": 1, "number": 1.0, "boolean": True, "array": [], "object": {}}.get(t, "sample")
    return out


class SOCPlaybookProvider(MockProvider):
    name = "mock"

    def __init__(self, model: str = "soc-playbook-mock"):
        super().__init__(responder=soc_playbook, model=model)


def build_mock(profile_model: str) -> MockProvider:
    if profile_model in {"soc-playbook", "soc-playbook-mock"}:
        return SOCPlaybookProvider()
    if profile_model in {"mock", "", None}:
        return SOCPlaybookProvider(model="mock")
    raise ProviderError(f"unknown mock model '{profile_model}'")

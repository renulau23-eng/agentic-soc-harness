"""Unit tests: tool schema derivation & validation, RBAC, policy engine, audit hashing, providers."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from ash.config import ModelProfile
from ash.core.errors import AuthorizationError, ToolValidationError
from ash.core.types import Message, PolicyDecision, Principal, RiskTier, Role, ToolSpec
from ash.governance.audit import compute_hash
from ash.governance.auth import hash_password, verify_password
from ash.governance.policy import PolicyConfig, PolicyEngine, PolicyRule
from ash.governance.rbac import RBAC
from ash.providers.mock import SOCPlaybookProvider
from ash.providers.nemotron import NemotronProvider, SovereignProvider
from ash.providers.openai_compat import OpenAICompatibleProvider
from ash.providers.router import ModelRouter, register_provider
from ash.tools.base import ToolRegistry, tool
from ash.tools.soc import isolate_host, lookup_ioc, release_host, search_siem


# ---------------------------------------------------------------- tools
def test_tool_decorator_derives_schema():
    @tool(risk_tier=RiskTier.MEDIUM)
    def sample(host: str, count: int = 3, verbose: bool = False) -> dict:
        """Do a sample thing."""
        return {"host": host, "count": count}

    spec = sample.spec()
    assert spec.name == "sample"
    assert spec.description == "Do a sample thing."
    assert spec.parameters["required"] == ["host"]
    assert spec.parameters["properties"]["count"] == {"type": "integer", "default": 3}
    assert spec.permission == "tools:execute:medium"
    assert not sample.accepts_context
    assert search_siem.accepts_context


def test_tool_validation_rejects_bad_args():
    with pytest.raises(ToolValidationError):
        search_siem.validate({"hours": 24})  # missing query
    with pytest.raises(ToolValidationError):
        search_siem.validate({"query": "x", "bogus": 1})
    with pytest.raises(ToolValidationError):
        search_siem.validate({"query": "x", "hours": "many"})
    cleaned = search_siem.validate({"query": "x", "hours": "48"})
    assert cleaned == {"query": "x", "hours": 48, "limit": 100}


def test_registry_rejects_duplicates():
    r = ToolRegistry()
    r.register(lookup_ioc)
    with pytest.raises(ValueError):
        r.register(lookup_ioc)
    assert "lookup_ioc" in r and r.names() == ["lookup_ioc"]


def test_openai_tool_shape():
    d = lookup_ioc.spec().to_openai()
    assert d["type"] == "function" and d["function"]["name"] == "lookup_ioc"
    assert "indicator" in d["function"]["parameters"]["properties"]


# ----------------------------------------------------------------- rbac
def test_rbac_roles_and_wildcards():
    rbac = RBAC()
    analyst = Principal(id="a", name="a", roles=["analyst"])
    lead = Principal(id="l", name="l", roles=["soc_lead"])
    admin = Principal(id="x", name="x", roles=["admin"])
    viewer = Principal(id="v", name="v", roles=["viewer"])
    assert rbac.has(analyst, "tools:execute:low")
    assert not rbac.has(analyst, "tools:execute:high")
    assert rbac.has(lead, "tools:execute:critical")  # wildcard
    assert rbac.has(admin, "anything:at:all")
    assert not rbac.has(viewer, "agents:run")
    with pytest.raises(AuthorizationError):
        rbac.require(viewer, "agents:run")
    assert rbac.can_execute_tier(lead, RiskTier.CRITICAL)


def test_unknown_role_grants_nothing():
    rbac = RBAC()
    p = Principal(id="p", name="p", roles=["ghost"])
    assert rbac.permissions_for(p) == set()


# --------------------------------------------------------------- policy
def test_policy_tier_defaults_and_escalation():
    engine = PolicyEngine(RBAC())
    analyst = Principal(id="a", name="a", roles=["analyst"])
    lead = Principal(id="l", name="l", roles=["soc_lead"])
    assert engine.evaluate(lookup_ioc, analyst).decision == PolicyDecision.ALLOW
    # analyst lacks HIGH → escalated to approval, never silently denied
    r = engine.evaluate(isolate_host, analyst, "respond")
    assert r.decision == PolicyDecision.REQUIRE_APPROVAL and "escalate" in (r.rule or "")
    # lead has HIGH but tier default still requires approval
    assert engine.evaluate(isolate_host, lead).decision == PolicyDecision.REQUIRE_APPROVAL
    assert engine.evaluate(release_host, lead).decision == PolicyDecision.REQUIRE_APPROVAL


def test_policy_rules_first_match_and_rbac_ceiling():
    cfg = PolicyConfig(
        rules=[
            PolicyRule(
                name="deny-release", decision=PolicyDecision.DENY, tools=["release_*"], reason="never automated"
            ),
            PolicyRule(
                name="triage-no-containment", decision=PolicyDecision.DENY, agents=["triage"], min_tier=RiskTier.HIGH
            ),
            PolicyRule(
                name="lead-auto-high", decision=PolicyDecision.ALLOW, min_tier=RiskTier.HIGH, roles=["soc_lead"]
            ),
        ]
    )
    engine = PolicyEngine(RBAC(), cfg)
    lead = Principal(id="l", name="l", roles=["soc_lead"])
    analyst = Principal(id="a", name="a", roles=["analyst"])
    assert engine.evaluate(release_host, lead).decision == PolicyDecision.DENY
    assert engine.evaluate(isolate_host, lead, "respond").decision == PolicyDecision.ALLOW
    # ALLOW rule cannot exceed RBAC: analyst still escalates
    assert engine.evaluate(isolate_host, analyst, "respond").decision == PolicyDecision.REQUIRE_APPROVAL
    assert engine.evaluate(isolate_host, lead, "triage").decision == PolicyDecision.DENY


def test_policy_deny_mode():
    engine = PolicyEngine(RBAC(), PolicyConfig(escalate_on_missing_permission=False))
    analyst = Principal(id="a", name="a", roles=["analyst"])
    assert engine.evaluate(isolate_host, analyst).decision == PolicyDecision.DENY


def test_policy_yaml_roundtrip(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(
        "rules:\n  - name: x\n    decision: deny\n    tools: ['release_host']\n"
        "roles:\n  ir_manager: ['agents:run', 'tools:execute:*', 'approvals:decide']\n"
    )
    cfg = PolicyConfig.from_yaml(str(p))
    engine = PolicyEngine(RBAC(), cfg)
    irm = Principal(id="i", name="i", roles=["ir_manager"])
    assert engine.rbac.has(irm, "tools:execute:critical")
    assert engine.evaluate(release_host, irm).decision == PolicyDecision.DENY


# ---------------------------------------------------------------- audit
def test_audit_hash_is_deterministic_and_tz_normalised():
    ts_aware = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    ts_naive = datetime(2026, 9, 26, 12, 0, 0)
    a = compute_hash("0" * 64, ts_aware, "u", "act", "t", {"k": 1})
    b = compute_hash("0" * 64, ts_naive, "u", "act", "t", {"k": 1})
    assert a == b and len(a) == 64
    assert compute_hash("1" * 64, ts_aware, "u", "act", "t", {"k": 1}) != a


# ----------------------------------------------------------------- auth
def test_password_hashing():
    h = hash_password("s3cret")
    assert h.startswith("pbkdf2$") and verify_password("s3cret", h) and not verify_password("nope", h)
    assert not verify_password("s3cret", "garbage")


# ------------------------------------------------------------ providers
def test_router_resolves_and_caches(monkeypatch):
    monkeypatch.setenv("ASH_MODEL_FAST_PROVIDER", "mock")
    from ash.config import Settings

    s = Settings(default_model_profile="fast")
    r = ModelRouter.from_settings(s)
    assert "fast" in r.profiles
    assert r.get("fast") is r.get()
    assert r.health() == {"fast": True}


def test_register_custom_provider():
    class Custom:
        name = "custom"
        model = "x"

        def chat(self, messages, tools=None, *, metadata=None):
            from ash.core.types import ModelResponse

            return ModelResponse(content="{}")

        def healthcheck(self):
            return True

    register_provider("custom_kind", lambda p: Custom())
    r = ModelRouter({"z": ModelProfile(name="z", provider="custom_kind", model="x")}, "z")
    assert r.get().name == "custom"


def _fake_server(capture: dict) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        capture["payload"] = json.loads(request.content)
        capture["auth"] = request.headers.get("authorization")
        return httpx.Response(
            200,
            json={
                "model": "nvidia/nemotron-3-super-120b-a12b",
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": "<think>I should enrich the IOC first.</think>",
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {"name": "lookup_ioc", "arguments": '{"indicator": "1.2.3.4"}'},
                                }
                            ],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150},
            },
        )

    return httpx.MockTransport(handler)


def test_nemotron_provider_injects_think_toggle_and_parses_tool_calls():
    cap: dict = {}
    profile = ModelProfile(
        name="reasoning",
        provider="nemotron",
        model="nvidia/nemotron-3-super-120b-a12b",
        base_url="http://nim.local/v1",
        api_key="k",
        reasoning=True,
    )
    prov = NemotronProvider(profile, transport=_fake_server(cap))
    msgs = [Message(role=Role.SYSTEM, content="You are triage."), Message(role=Role.USER, content="{}")]
    tools = [
        ToolSpec(
            name="lookup_ioc",
            description="d",
            parameters={"type": "object", "properties": {}},
            risk_tier=RiskTier.LOW,
            permission="tools:execute:low",
        )
    ]
    resp = prov.chat(msgs, tools)
    assert cap["payload"]["messages"][0]["content"].startswith("/think")
    assert cap["payload"]["tools"][0]["function"]["name"] == "lookup_ioc"
    assert cap["auth"] == "Bearer k"
    assert resp.tool_calls[0].name == "lookup_ioc" and resp.tool_calls[0].arguments == {"indicator": "1.2.3.4"}
    assert resp.reasoning and "enrich" in resp.reasoning
    assert resp.content in (None, "")
    assert resp.usage.total_tokens == 150 and resp.provider == "nemotron"


def test_nemotron_no_think_and_text_tool_call_fallback():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": '<tool_call>{"name": "search_siem", "arguments": {"query": "x"}}</tool_call>',
                        }
                    }
                ]
            },
        )

    profile = ModelProfile(name="fast", provider="nemotron", model="m", base_url="http://x/v1", reasoning=False)
    prov = NemotronProvider(profile, transport=httpx.MockTransport(handler))
    out = prov.prepare_messages([Message(role=Role.USER, content="hi")])
    assert out[0].role == Role.SYSTEM and out[0].content == "/no_think"
    resp = prov.chat([Message(role=Role.USER, content="hi")])
    assert resp.tool_calls[0].name == "search_siem" and resp.tool_calls[0].arguments == {"query": "x"}


def test_sovereign_provider_preamble():
    profile = ModelProfile(
        name="sov",
        provider="sovereign",
        model="ey-sovereign-7b",
        base_url="http://s/v1",
        extra={"system_preamble": "[SOC-ADAPTER v1]"},
    )
    prov = SovereignProvider(
        profile, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"choices": []}))
    )
    out = prov.prepare_messages([Message(role=Role.SYSTEM, content="base")])
    assert out[0].content.startswith("[SOC-ADAPTER v1]")


def test_openai_provider_retries_then_fails():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, text="busy")

    profile = ModelProfile(
        name="p", provider="openai_compatible", model="m", base_url="http://x/v1", extra={"max_retries": 2}
    )
    prov = OpenAICompatibleProvider(profile, transport=httpx.MockTransport(handler))
    import time as _t

    orig = _t.sleep
    _t.sleep = lambda *_: None
    try:
        from ash.core.errors import ProviderError

        with pytest.raises(ProviderError):
            prov.chat([Message(role=Role.USER, content="x")])
    finally:
        _t.sleep = orig
    assert calls["n"] == 2


def test_playbook_provider_is_deterministic():
    p = SOCPlaybookProvider()
    msgs = [Message(role=Role.USER, content=json.dumps({"alert": {"indicators": ["185.220.101.45"]}}))]
    tools = [lookup_ioc.spec()]
    r1 = p.chat(msgs, tools, metadata={"agent": "triage"})
    assert r1.tool_calls[0].name == "lookup_ioc"

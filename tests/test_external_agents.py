from __future__ import annotations

import httpx

from ash.agents.external import CallbackResult
from tests.conftest import token_for


def _registration(endpoint: str = "http://agent.test/execute") -> dict:
    return {
        "name": "remote-triage",
        "version": "1.2.0",
        "capabilities": ["triage"],
        "transport": "http",
        "endpoint": endpoint,
        "health_endpoint": "http://agent.test/health",
        "scopes": ["fabric:read", "threat_intel:read"],
        "limits": {"timeout_seconds": 2, "max_concurrency": 2, "failure_threshold": 2,
                   "recovery_seconds": 5},
    }


def test_registration_discovery_rotation_and_rbac(client):
    admin = token_for(client, "admin", "admin-pass")
    viewer = token_for(client, "vik", "vik-pass")
    assert client.post("/api/v1/external-agents", headers=viewer, json=_registration()).status_code == 403

    created = client.post("/api/v1/external-agents", headers=admin, json=_registration())
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["api_key"].startswith("ash_agent_")
    agent_id = body["agent"]["id"]
    assert client.get("/api/v1/external-agents?capability=triage", headers=viewer).json()[0]["id"] == agent_id

    updated = client.patch(
        f"/api/v1/external-agents/{agent_id}", headers=admin, json={"enabled": False}
    )
    assert updated.json()["status"] == "disabled"
    rotated = client.post(f"/api/v1/external-agents/{agent_id}/credentials", headers=admin)
    assert rotated.status_code == 200 and rotated.json()["api_key"] != body["api_key"]


def test_dispatch_idempotency_and_owned_callback(client, harness, monkeypatch):
    admin = token_for(client, "admin", "admin-pass")
    registered = client.post("/api/v1/external-agents", headers=admin, json=_registration()).json()
    agent_key = registered["api_key"]

    def handler(request: httpx.Request) -> httpx.Response:
        payload = __import__("json").loads(request.content)
        return httpx.Response(
            200,
            json={"protocol_version": "1.0", "invocation_id": payload["invocation_id"],
                  "status": "accepted", "output": {}, "decisions": [], "metrics": {}},
        )

    monkeypatch.setattr(
        harness.external_agents,
        "_client",
        lambda _agent: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    dispatch = {"capability": "triage", "event": {"severity": "high"},
                "idempotency_key": "alert-42", "asynchronous": False}
    first = client.post("/api/v1/external-agent-dispatch", headers=admin, json=dispatch)
    assert first.status_code == 202, first.text
    invocation_id = first.json()[0]["id"]
    second = client.post("/api/v1/external-agent-dispatch", headers=admin, json=dispatch)
    assert second.json()[0]["id"] == invocation_id

    result = CallbackResult(status="completed", output={"verdict": "malicious"})
    callback = client.post(
        f"/api/v1/external-agent-invocations/{invocation_id}/callback",
        headers={"X-Agent-Key": agent_key},
        json=result.model_dump(mode="json"),
    )
    assert callback.status_code == 200 and callback.json()["result"]["output"]["verdict"] == "malicious"
    assert client.post(
        f"/api/v1/external-agent-invocations/{invocation_id}/callback",
        headers={"X-Agent-Key": "wrong"},
        json=result.model_dump(mode="json"),
    ).status_code == 401


def test_protocol_major_version_rejected(client):
    admin = token_for(client, "admin", "admin-pass")
    body = _registration()
    body["protocol_version"] = "2.0"
    assert client.post("/api/v1/external-agents", headers=admin, json=body).status_code == 422

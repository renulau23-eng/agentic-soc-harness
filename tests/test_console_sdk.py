"""Installed console delivery and real external-agent protocol boundaries."""

from fastapi.testclient import TestClient

from ash.agents.sdk import ExternalAgentApplication


def test_console_assets_and_case_evidence(client):
    for path, content in [("/", "Clarity at every"), ("/assets/app.js", "openCase"), ("/assets/app.css", ".hero")]:
        response = client.get(path)
        assert response.status_code == 200
        assert content in response.text
    assert client.get("/api/v1/cases").status_code == 401
    headers = {"X-API-Key": "admin-key"}
    created = client.post(
        "/api/v1/alerts", headers=headers, json={"source": "fabric", "title": "Console evidence", "severity": "high"}
    )
    case_id = created.json()["case_id"]
    detail = client.get(f"/api/v1/cases/{case_id}", headers=headers).json()
    assert detail["alerts"][0]["title"] == "Console evidence"
    evidence = client.get(f"/api/v1/cases/{case_id}/evidence", headers=headers).json()
    assert evidence["audit_chain"]["ok"] is True
    assert evidence["case"]["id"] == case_id


def test_sdk_http_and_mcp_require_bearer_credentials():
    agent = ExternalAgentApplication("test-triage", "1.0.0", "test-secret")

    @agent.capability("triage")
    def triage(request):
        return {"status": "completed", "output": {"verdict": "review"}}

    client = TestClient(agent.app)
    assert client.get("/health").json()["capabilities"] == ["triage"]
    request = {
        "invocation_id": "inv_test",
        "capability": "triage",
        "event": {},
        "callback_url": "http://control.test/callback",
        "deadline": "2030-01-01T00:00:00Z",
    }
    headers = {"Authorization": "Bearer test-secret"}
    assert client.post("/execute", json=request).status_code == 401
    result = client.post("/execute", json=request, headers=headers)
    assert result.status_code == 200, result.text
    assert result.json()["output"]["verdict"] == "review"
    unsupported = {**request, "capability": "unknown"}
    assert client.post("/execute", json=unsupported, headers=headers).status_code == 422
    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "execute_security_agent", "arguments": request},
    }
    assert client.post("/mcp", json=rpc).status_code == 401
    result = client.post("/mcp", json=rpc, headers=headers)
    assert result.status_code == 200, result.text
    assert result.json()["result"]["structuredContent"]["invocation_id"] == "inv_test"
    assert client.post("/mcp", json={"id": 2, "method": "unknown"}).json()["error"]["code"] == -32601

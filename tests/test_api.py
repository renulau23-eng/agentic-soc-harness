"""API tests via FastAPI TestClient: auth, RBAC on endpoints, full incident over HTTP, ops endpoints."""

from __future__ import annotations

from tests.conftest import token_for

ALERT = {
    "source": "siem",
    "title": "Beaconing to known C2 from FIN-WS-042",
    "severity": "high",
    "indicators": ["185.220.101.45"],
    "asset_id": "host-fin-042",
}


def test_health_and_metrics_public(client):
    assert client.get("/health").json()["ok"] is True
    r = client.get("/ready")
    assert r.status_code == 200 and r.json()["database"] is True
    assert "ash_http_requests_total" in client.get("/metrics").text


def test_auth_required_and_bad_token(client):
    assert client.get("/api/v1/agents").status_code == 401
    assert client.get("/api/v1/agents", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/api/v1/agents", headers={"X-API-Key": "wrong"}).status_code == 401
    r = client.post("/api/v1/auth/token", json={"username": "asha", "password": "wrong"})
    assert r.status_code == 401


def test_api_key_service_principal(client):
    r = client.get("/api/v1/auth/me", headers={"X-API-Key": "siem-key"})
    assert r.status_code == 200 and r.json()["kind"] == "service" and "alerts:ingest" in r.json()["permissions"]
    r = client.post("/api/v1/alerts", json=ALERT, headers={"X-API-Key": "siem-key"})
    assert r.status_code == 201 and r.json()["case_id"].startswith("case_")


def test_bootstrap_admin_token(client):
    h = token_for(client, "admin", "admin-pass")
    assert client.get("/api/v1/audit/verify", headers=h).json()["ok"]


def test_catalog_endpoints(client):
    h = token_for(client, "vik", "vik-pass")  # viewer can read catalog
    agents = client.get("/api/v1/agents", headers=h).json()
    assert {a["name"] for a in agents} == {"triage", "investigate", "respond"}
    tools = client.get("/api/v1/tools", headers=h).json()
    assert any(t["name"] == "isolate_host" and t["risk_tier"] == "high" for t in tools)
    wfs = client.get("/api/v1/workflows", headers=h).json()
    assert wfs[0]["name"] == "triage_investigate_respond" and len(wfs[0]["stages"]) == 3
    assert "reasoning" in client.get("/api/v1/models", headers=h).json()


def test_rbac_on_endpoints(client):
    viewer = token_for(client, "vik", "vik-pass")
    assert client.post("/api/v1/alerts", json=ALERT, headers=viewer).status_code == 403
    assert client.post("/api/v1/runs", json={"target": "triage"}, headers=viewer).status_code == 403
    assert client.get("/api/v1/audit", headers=viewer).status_code == 403
    analyst = token_for(client, "asha", "asha-pass")
    assert client.get("/api/v1/audit/verify", headers=analyst).status_code == 403


def test_full_incident_over_http(client):
    analyst = token_for(client, "asha", "asha-pass")
    lead = token_for(client, "rahul", "rahul-pass")
    auditor = token_for(client, "meera", "meera-pass")

    case_id = client.post("/api/v1/alerts", json=ALERT, headers=analyst).json()["case_id"]
    r = client.post("/api/v1/runs", json={"target": "triage_investigate_respond", "case_id": case_id}, headers=analyst)
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["status"] == "awaiting_approval" and run["pending_approval_id"]
    assert any(s["type"] == "approval" and s["name"] == "isolate_host" for s in run["steps"])

    pend = client.get("/api/v1/approvals", headers=lead).json()
    assert len(pend) == 1 and pend[0]["tool"] == "isolate_host"
    # analyst cannot approve (no permission → 403)
    r = client.post(f"/api/v1/approvals/{pend[0]['id']}/decide", json={"approve": True}, headers=analyst)
    assert r.status_code == 403

    r = client.post(f"/api/v1/approvals/{pend[0]['id']}/decide", json={"approve": True, "note": "ok"}, headers=lead)
    assert r.status_code == 200, r.text
    assert r.json()["approval"]["status"] == "approved"
    run = r.json()["run"]
    while run["status"] == "awaiting_approval":
        nxt = client.get("/api/v1/approvals", headers=lead).json()[0]
        run = client.post(f"/api/v1/approvals/{nxt['id']}/decide", json={"approve": True}, headers=lead).json()["run"]
    assert run["status"] == "succeeded"

    # double-decide → 409
    r = client.post(f"/api/v1/approvals/{pend[0]['id']}/decide", json={"approve": True}, headers=lead)
    assert r.status_code == 409

    case = client.get(f"/api/v1/cases/{case_id}", headers=analyst).json()
    assert case["status"] == "contained" and len(case["runs"]) == 1
    assert client.get("/api/v1/cases?status=contained", headers=analyst).json()[0]["id"] == case_id

    detail = client.get(f"/api/v1/runs/{run['id']}", headers=analyst).json()
    assert detail["output"]["output"]["final"]["contained"] is True

    ev = client.get(f"/api/v1/cases/{case_id}/evidence", headers=auditor).json()
    assert ev["audit_chain"]["ok"] and len(ev["approvals"]) == 2
    assert client.get("/api/v1/audit/verify", headers=auditor).json()["ok"]
    audit = client.get(f"/api/v1/audit?case_id={case_id}&action=approval.approved", headers=auditor).json()
    assert len(audit) == 2

    r = client.post(f"/api/v1/cases/{case_id}/status", json={"status": "resolved", "note": "clean"}, headers=lead)
    assert r.json()["status"] == "resolved"
    # resume on a finished run → 409
    assert client.post(f"/api/v1/runs/{run['id']}/resume", headers=lead).status_code == 409


def test_404s(client):
    h = token_for(client, "asha", "asha-pass")
    assert client.get("/api/v1/cases/case_nope", headers=h).status_code == 404
    assert client.get("/api/v1/runs/run_nope", headers=h).status_code == 404
    assert client.post("/api/v1/runs", json={"target": "ghost"}, headers=h).status_code == 404


def test_validation_422(client):
    h = token_for(client, "asha", "asha-pass")
    assert client.post("/api/v1/alerts", json={"title": "x"}, headers=h).status_code == 422
    assert client.post("/api/v1/cases/x/status", json={"status": "bogus"}, headers=h).status_code == 422

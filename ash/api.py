"""FastAPI application exposing the harness."""

# No `from __future__ import annotations` here: FastAPI must see real
# annotation objects for the locally-defined dependency alias to resolve.

from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ash import __version__
from ash.agents.external import (
    AgentPatch,
    AgentRegistrationRequest,
    AgentRoute,
    CallbackResult,
    DispatchRequest,
    external_row,
)
from ash.config import Settings, get_settings
from ash.core.errors import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    GuardrailBlocked,
    HarnessError,
    NotFound,
    RateLimited,
)
from ash.core.types import AlertIn, CaseStatus, Principal
from ash.observability import get_logger, metrics
from ash.runtime import Harness, _row

log = get_logger(__name__)


# --------------------------------------------------------------------------- #
# request/response models
# --------------------------------------------------------------------------- #


class TokenRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    roles: list[str]


class RunRequest(BaseModel):
    target: str = Field(description="Agent or workflow name")
    case_id: str | None = None
    input: dict[str, Any] = Field(default_factory=dict)
    model_profile: str | None = None


class DecisionRequest(BaseModel):
    approve: bool
    note: str | None = None
    auto_resume: bool = True


class CaseStatusRequest(BaseModel):
    status: CaseStatus
    note: str = ""


# --------------------------------------------------------------------------- #
# app factory
# --------------------------------------------------------------------------- #


def create_app(harness: Harness | None = None, settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    hz = harness or Harness.build(settings)

    app = FastAPI(
        title="Agentic SOC Harness",
        version=__version__,
        description="Model-agnostic, governance-first runtime for security agents.",
    )
    app.state.harness = hz
    static_dir = Path(__file__).parent / "static"
    app.mount("/assets", StaticFiles(directory=static_dir), name="assets")

    @app.get("/", include_in_schema=False)
    def operator_console() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    # ---- auth dependency ------------------------------------------------ #
    def current_principal(
        authorization: Annotated[str | None, Header()] = None, x_api_key: Annotated[str | None, Header()] = None
    ) -> Principal:
        try:
            if x_api_key:
                return hz.auth.principal_from_api_key(x_api_key)
            if authorization and authorization.lower().startswith("bearer "):
                return hz.auth.principal_from_token(authorization.split(" ", 1)[1].strip())
        except AuthenticationError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        raise HTTPException(status_code=401, detail="missing credentials")

    P = Annotated[Principal, Depends(current_principal)]

    # ---- error mapping -------------------------------------------------- #
    _status: list[tuple[type[Exception], int]] = [
        (AuthenticationError, 401),
        (AuthorizationError, 403),
        (NotFound, 404),
        (RateLimited, 429),
        (GuardrailBlocked, 422),
        (ConfigurationError, 500),
        (ValueError, 400),
        (HarnessError, 409),
    ]

    @app.exception_handler(HarnessError)
    @app.exception_handler(ValueError)
    async def _handle_known(request: Request, exc: Exception) -> JSONResponse:
        for cls, code in _status:
            if isinstance(exc, cls):
                metrics.inc("ash_http_errors_total", status=str(code))
                return JSONResponse(status_code=code, content={"error": type(exc).__name__, "detail": str(exc)})
        return await _handle_unknown(request, exc)

    @app.exception_handler(Exception)
    async def _handle_unknown(request: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled error", exc_info=True, path=str(request.url.path))
        metrics.inc("ash_http_errors_total", status="500")
        return JSONResponse(status_code=500, content={"error": "InternalError", "detail": "internal server error"})

    @app.middleware("http")
    async def _count(request: Request, call_next: Callable[[Request], Any]) -> Response:
        resp: Response = await call_next(request)
        metrics.inc("ash_http_requests_total", method=request.method, status=str(resp.status_code))
        return resp

    # ---- ops ------------------------------------------------------------ #
    @app.get("/health", tags=["ops"])
    def health() -> dict[str, Any]:
        return {"ok": True, "version": __version__, "environment": settings.environment}

    @app.get("/ready", tags=["ops"])
    def ready() -> JSONResponse:
        r = hz.readiness()
        return JSONResponse(status_code=200 if r["ok"] else 503, content=r)

    @app.get("/metrics", tags=["ops"], response_class=PlainTextResponse)
    def prom() -> str:
        return metrics.render_prometheus()

    # ---- auth ----------------------------------------------------------- #
    @app.post("/api/v1/auth/token", response_model=TokenResponse, tags=["auth"])
    def token(body: TokenRequest) -> TokenResponse:
        principal = hz.auth.authenticate_password(body.username, body.password)
        hz.audit.record(actor=principal.id, action="auth.login", target=principal.id)
        return TokenResponse(access_token=hz.auth.issue_token(principal), roles=principal.roles)

    @app.get("/api/v1/auth/me", tags=["auth"])
    def me(principal: P) -> dict[str, Any]:
        return {**principal.model_dump(), "permissions": sorted(hz.rbac.permissions_for(principal))}

    # ---- catalog -------------------------------------------------------- #
    @app.get("/api/v1/agents", tags=["catalog"])
    def agents(principal: P) -> list[dict[str, Any]]:
        hz.rbac.require(principal, "agents:read")
        return hz.agents.describe()

    @app.get("/api/v1/workflows", tags=["catalog"])
    def workflows(principal: P) -> list[dict[str, Any]]:
        hz.rbac.require(principal, "agents:read")
        return hz.workflows.describe()

    @app.get("/api/v1/tools", tags=["catalog"])
    def tools(principal: P) -> list[dict[str, Any]]:
        hz.rbac.require(principal, "tools:read")
        return [t.model_dump() for t in hz.tools.specs()]

    @app.get("/api/v1/models", tags=["catalog"])
    def models(principal: P) -> dict[str, Any]:
        hz.rbac.require(principal, "agents:read")
        return {
            name: {"provider": p.provider, "model": p.model, "reasoning": p.reasoning}
            for name, p in hz.router.profiles.items()
        }

    # ---- external agent plug-in runtime ------------------------------- #
    @app.post("/api/v1/external-agents", status_code=201, tags=["external agents"])
    def register_external_agent(body: AgentRegistrationRequest, principal: P) -> dict[str, Any]:
        hz.rbac.require(principal, "external_agents:write")
        agent, api_key = hz.external_agents.registry.register(body)
        hz.audit.record(
            actor=principal.id,
            action="external_agent.registered",
            target=agent.id,
            detail={"name": agent.name, "version": agent.version, "capabilities": agent.capabilities},
        )
        return {"agent": external_row(agent), "api_key": api_key,
                "warning": "Store this credential now. It cannot be recovered."}

    @app.get("/api/v1/external-agents", tags=["external agents"])
    def discover_external_agents(principal: P, capability: str | None = None) -> list[dict[str, Any]]:
        hz.rbac.require(principal, "external_agents:read")
        return [external_row(a) for a in hz.external_agents.registry.list(capability)]

    @app.get("/api/v1/external-agents/{agent_id}", tags=["external agents"])
    def get_external_agent(agent_id: str, principal: P) -> dict[str, Any]:
        hz.rbac.require(principal, "external_agents:read")
        return external_row(hz.external_agents.registry.get(agent_id))

    @app.patch("/api/v1/external-agents/{agent_id}", tags=["external agents"])
    def configure_external_agent(agent_id: str, body: AgentPatch, principal: P) -> dict[str, Any]:
        hz.rbac.require(principal, "external_agents:write")
        agent = hz.external_agents.registry.patch(agent_id, body)
        hz.audit.record(actor=principal.id, action="external_agent.configured", target=agent_id,
                        detail={"changed": sorted(body.model_fields_set)})
        return external_row(agent)

    @app.post("/api/v1/external-agents/{agent_id}/credentials", tags=["external agents"])
    def rotate_external_agent_credential(agent_id: str, principal: P) -> dict[str, Any]:
        hz.rbac.require(principal, "external_agents:write")
        api_key = hz.external_agents.registry.rotate_credential(agent_id)
        hz.audit.record(actor=principal.id, action="external_agent.credential_rotated", target=agent_id)
        return {"agent_id": agent_id, "api_key": api_key,
                "warning": "Previous credentials were revoked. Store this credential now."}

    @app.post("/api/v1/external-agents/{agent_id}/health", tags=["external agents"])
    def probe_external_agent(agent_id: str, principal: P) -> dict[str, Any]:
        hz.rbac.require(principal, "external_agents:write")
        return external_row(hz.external_agents.health(agent_id))

    @app.get("/api/v1/external-agent-routes", tags=["external agents"])
    def external_agent_routes(principal: P) -> list[dict[str, Any]]:
        hz.rbac.require(principal, "external_agents:read")
        return [external_row(r) for r in hz.external_agents.registry.routes()]

    @app.put("/api/v1/external-agent-routes/{capability}", tags=["external agents"])
    def configure_external_agent_route(capability: str, body: AgentRoute, principal: P) -> dict[str, Any]:
        hz.rbac.require(principal, "external_agents:write")
        if body.capability != capability:
            raise ValueError("route capability must match the path")
        route = hz.external_agents.registry.save_route(body)
        hz.audit.record(actor=principal.id, action="external_agent.route_configured", target=capability,
                        detail={"agent_ids": body.agent_ids, "strategy": body.strategy})
        return external_row(route)

    @app.post("/api/v1/external-agent-dispatch", status_code=202, tags=["external agents"])
    def dispatch_external_agent(body: DispatchRequest, principal: P) -> list[dict[str, Any]]:
        hz.rbac.require(principal, "external_agents:run")
        invocations = hz.external_agents.create_invocations(body)
        output = []
        for invocation in invocations:
            if body.asynchronous and hz.broker.distributed:
                hz.broker.publish(invocation.id)
            else:
                invocation = hz.external_agents.execute(invocation.id)
            output.append(external_row(invocation))
            hz.audit.record(actor=principal.id, action="external_agent.dispatched", target=invocation.id,
                            run_id=body.run_id, detail={"capability": body.capability,
                                                       "agent_id": invocation.agent_id})
        return output

    @app.get("/api/v1/external-agent-invocations", tags=["external agents"])
    def external_agent_invocations(
        principal: P, limit: Annotated[int, Query(ge=1, le=500)] = 100
    ) -> list[dict[str, Any]]:
        hz.rbac.require(principal, "external_agents:read")
        return [external_row(i) for i in hz.external_agents.list_invocations(limit)]

    @app.get("/api/v1/external-agent-invocations/{invocation_id}", tags=["external agents"])
    def external_agent_invocation(invocation_id: str, principal: P) -> dict[str, Any]:
        hz.rbac.require(principal, "external_agents:read")
        return external_row(hz.external_agents.get_invocation(invocation_id))

    @app.post("/api/v1/external-agent-invocations/{invocation_id}/callback", tags=["external agents"])
    def external_agent_callback(
        invocation_id: str,
        body: CallbackResult,
        x_agent_key: Annotated[str | None, Header()] = None,
    ) -> dict[str, Any]:
        if not x_agent_key:
            raise HTTPException(status_code=401, detail="missing X-Agent-Key")
        credential = hz.external_agents.registry.authenticate(x_agent_key)
        if not credential or "agent:callback" not in credential.scopes:
            raise HTTPException(status_code=401, detail="invalid agent credential")
        try:
            row = hz.external_agents.callback(invocation_id, body, credential.agent_id)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        hz.audit.record(actor=f"agent:{credential.agent_id}", action="external_agent.callback",
                        target=invocation_id, run_id=row.run_id, detail={"status": row.status})
        return external_row(row)

    # ---- alerts & cases ------------------------------------------------- #
    @app.post("/api/v1/alerts", status_code=201, tags=["cases"])
    def ingest(alert: AlertIn, principal: P) -> dict[str, Any]:
        case, alert_id = hz.ingest_alert(alert, principal)
        return {"case_id": case.id, "alert_id": alert_id, "status": case.status}

    @app.get("/api/v1/cases", tags=["cases"])
    def list_cases(
        principal: P, status: str | None = None, limit: Annotated[int, Query(ge=1, le=500)] = 100
    ) -> list[dict[str, Any]]:
        return [_row(c) for c in hz.list_cases(principal, status=status, limit=limit)]

    @app.get("/api/v1/cases/{case_id}", tags=["cases"])
    def get_case(case_id: str, principal: P) -> dict[str, Any]:
        case = hz.get_case(case_id, principal)
        return {
            **_row(case),
            "alerts": [_row(a) for a in hz.repo.list_alerts(case_id)],
            "runs": [_row(r) for r in hz.repo.list_runs(case_id=case_id)],
        }

    @app.post("/api/v1/cases/{case_id}/status", tags=["cases"])
    def set_status(case_id: str, body: CaseStatusRequest, principal: P) -> dict[str, Any]:
        return _row(hz.set_case_status(case_id, body.status, principal, body.note))

    @app.get("/api/v1/cases/{case_id}/evidence", tags=["cases"])
    def evidence(case_id: str, principal: P) -> dict[str, Any]:
        return hz.evidence_pack(case_id, principal)

    # ---- runs ----------------------------------------------------------- #
    @app.post("/api/v1/runs", status_code=201, tags=["runs"])
    def start_run(body: RunRequest, principal: P) -> dict[str, Any]:
        run = hz.start_run(
            target=body.target,
            principal=principal,
            case_id=body.case_id,
            input=body.input,
            model_profile=body.model_profile,
        )
        return hz.get_run(run.id, principal)

    @app.get("/api/v1/runs/{run_id}", tags=["runs"])
    def get_run(run_id: str, principal: P) -> dict[str, Any]:
        return hz.get_run(run_id, principal)

    @app.post("/api/v1/runs/{run_id}/resume", tags=["runs"])
    def resume(run_id: str, principal: P) -> dict[str, Any]:
        run = hz.resume_run(run_id, principal)
        return hz.get_run(run.id, principal)

    # ---- approvals ------------------------------------------------------ #
    @app.get("/api/v1/approvals", tags=["approvals"])
    def approvals(principal: P, status: str | None = "pending", case_id: str | None = None) -> list[dict[str, Any]]:
        return [_row(a) for a in hz.list_approvals(principal, status=status, case_id=case_id)]

    @app.post("/api/v1/approvals/{approval_id}/decide", tags=["approvals"])
    def decide(approval_id: str, body: DecisionRequest, principal: P) -> dict[str, Any]:
        approval, run = hz.decide_approval(
            approval_id, approve=body.approve, principal=principal, note=body.note, auto_resume=body.auto_resume
        )
        return {"approval": _row(approval), "run": _row(run) if run else None}

    # ---- audit ---------------------------------------------------------- #
    @app.get("/api/v1/audit", tags=["audit"])
    def audit(
        principal: P,
        case_id: str | None = None,
        run_id: str | None = None,
        action: str | None = None,
        limit: Annotated[int, Query(ge=1, le=5000)] = 500,
    ) -> list[dict[str, Any]]:
        return hz.list_audit(principal, case_id=case_id, run_id=run_id, action=action, limit=limit)

    @app.get("/api/v1/audit/verify", tags=["audit"])
    def verify(principal: P) -> dict[str, Any]:
        return hz.verify_audit(principal)

    return app

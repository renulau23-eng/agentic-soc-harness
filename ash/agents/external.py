"""Durable, versioned runtime for independently deployed SOC agents."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError

from ash.core.errors import HarnessError, NotFound
from ash.core.types import new_id
from ash.observability import get_logger, metrics
from ash.persistence.models import (
    ExternalAgentCredentialRow,
    ExternalAgentInvocationRow,
    ExternalAgentRouteRow,
    ExternalAgentRow,
)
from ash.persistence.repository import Database

PROTOCOL_VERSION = "1.0"
log = get_logger(__name__)


def _now() -> datetime:
    return datetime.now(UTC)


class AgentAuth(BaseModel):
    type: Literal["none", "bearer", "oauth2_client_credentials", "workload_identity", "mtls"] = "none"
    secret_ref: str | None = None
    token_url: str | None = None
    client_id: str | None = None
    audience: str | None = None
    ca_cert_ref: str | None = None
    client_cert_ref: str | None = None
    client_key_ref: str | None = None


class AgentLimits(BaseModel):
    timeout_seconds: float = Field(default=15, ge=0.1, le=300)
    max_concurrency: int = Field(default=4, ge=1, le=100)
    failure_threshold: int = Field(default=3, ge=1, le=20)
    recovery_seconds: int = Field(default=30, ge=1, le=3600)


class AgentRegistrationRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    version: str = Field(min_length=1, max_length=40)
    protocol_version: str = PROTOCOL_VERSION
    description: str = ""
    capabilities: list[str] = Field(min_length=1)
    transport: Literal["http", "grpc", "mcp"] = "http"
    endpoint: str
    health_endpoint: str | None = None
    enabled: bool = True
    scopes: set[str] = Field(default_factory=lambda: {"fabric:read"})
    auth: AgentAuth = Field(default_factory=AgentAuth)
    limits: AgentLimits = Field(default_factory=AgentLimits)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("protocol_version")
    @classmethod
    def supported_protocol(cls, value: str) -> str:
        if value.split(".", 1)[0] != PROTOCOL_VERSION.split(".", 1)[0]:
            raise ValueError(f"unsupported protocol version {value}")
        return value


class AgentPatch(BaseModel):
    endpoint: str | None = None
    health_endpoint: str | None = None
    enabled: bool | None = None
    capabilities: list[str] | None = None
    scopes: set[str] | None = None
    auth: AgentAuth | None = None
    limits: AgentLimits | None = None
    metadata: dict[str, Any] | None = None


class AgentRoute(BaseModel):
    capability: str
    agent_ids: list[str]
    strategy: Literal["priority", "fanout"] = "priority"
    enabled: bool = True


class ExecutionRequest(BaseModel):
    protocol_version: str = PROTOCOL_VERSION
    invocation_id: str
    capability: str
    event: dict[str, Any]
    context: dict[str, Any] = Field(default_factory=dict)
    callback_url: str
    deadline: datetime
    trace_context: dict[str, str] = Field(default_factory=dict)


class ExecutionResult(BaseModel):
    protocol_version: str = PROTOCOL_VERSION
    invocation_id: str
    status: Literal["accepted", "completed", "failed"] = "completed"
    output: dict[str, Any] = Field(default_factory=dict)
    decisions: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None
    metrics: dict[str, float] = Field(default_factory=dict)


class CallbackResult(BaseModel):
    protocol_version: str = PROTOCOL_VERSION
    status: Literal["completed", "failed"]
    output: dict[str, Any] = Field(default_factory=dict)
    decisions: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None
    metrics: dict[str, float] = Field(default_factory=dict)


class DispatchRequest(BaseModel):
    capability: str
    event: dict[str, Any]
    context: dict[str, Any] = Field(default_factory=dict)
    run_id: str | None = None
    idempotency_key: str | None = None
    asynchronous: bool = True


class SecretResolver:
    def __init__(self, root: str, allow_literal: bool) -> None:
        self.root = Path(root).resolve()
        self.allow_literal = allow_literal

    def value(self, ref: str | None) -> str | None:
        if not ref:
            return None
        if ref.startswith("env://"):
            return os.environ.get(ref[6:])
        if ref.startswith("file://"):
            path = Path(ref[7:]).resolve()
            if self.root not in path.parents and path != self.root:
                raise ValueError("secret path is outside ASH_SECRETS_DIR")
            return path.read_text(encoding="utf-8").strip()
        if self.allow_literal:
            return ref
        raise ValueError("secret references must use env:// or file://")

    def path(self, ref: str | None) -> str | None:
        if not ref:
            return None
        value = self.value(ref) if ref.startswith("env://") else ref[7:] if ref.startswith("file://") else ref
        if not self.allow_literal and not ref.startswith(("env://", "file://")):
            raise ValueError("TLS paths must use env:// or file://")
        return str(Path(value).resolve())


class ExternalAgentRegistry:
    def __init__(self, db: Database) -> None:
        self.db = db

    def register(self, body: AgentRegistrationRequest) -> tuple[ExternalAgentRow, str]:
        row = ExternalAgentRow(
            id=new_id("xagent"),
            name=body.name,
            version=body.version,
            protocol_version=body.protocol_version,
            description=body.description,
            transport=body.transport,
            endpoint=body.endpoint,
            health_endpoint=body.health_endpoint,
            capabilities=sorted(set(body.capabilities)),
            scopes=sorted(body.scopes),
            auth=body.auth.model_dump(mode="json"),
            limits=body.limits.model_dump(mode="json"),
            metadata_=body.metadata,
            enabled=body.enabled,
            status="unknown" if body.enabled else "disabled",
        )
        token = f"ash_agent_{secrets.token_urlsafe(32)}"
        digest = hashlib.sha256(token.encode()).hexdigest()
        credential = ExternalAgentCredentialRow(
            id=new_id("cred"),
            agent_id=row.id,
            key_hash=digest,
            scopes=sorted(set(body.scopes) | {"agent:callback", "agent:self"}),
        )
        try:
            with self.db.session() as session:
                session.add(row)
                session.flush()
                session.add(credential)
        except IntegrityError as exc:
            raise ValueError(f"agent {body.name}@{body.version} is already registered") from exc
        return row, token

    def list(self, capability: str | None = None) -> list[ExternalAgentRow]:
        with self.db.session() as session:
            rows = list(session.scalars(select(ExternalAgentRow).order_by(ExternalAgentRow.name)))
            return [r for r in rows if not capability or capability in r.capabilities]

    def get(self, agent_id: str) -> ExternalAgentRow:
        with self.db.session() as session:
            row = session.get(ExternalAgentRow, agent_id)
            if not row:
                raise NotFound(f"external agent {agent_id} not found")
            return row

    def patch(self, agent_id: str, body: AgentPatch) -> ExternalAgentRow:
        with self.db.session() as session:
            row = session.get(ExternalAgentRow, agent_id)
            if not row:
                raise NotFound(f"external agent {agent_id} not found")
            for key in body.model_fields_set:
                value = getattr(body, key)
                if value is None:
                    continue
                if isinstance(value, BaseModel):
                    value = value.model_dump(mode="json")
                elif isinstance(value, set):
                    value = sorted(value)
                setattr(row, "metadata_" if key == "metadata" else key, value)
            row.status = "disabled" if not row.enabled else row.status
            row.updated_at = _now()
            session.flush()
            return row

    def rotate_credential(self, agent_id: str) -> str:
        agent = self.get(agent_id)
        token = f"ash_agent_{secrets.token_urlsafe(32)}"
        with self.db.session() as session:
            for row in session.scalars(
                select(ExternalAgentCredentialRow).where(ExternalAgentCredentialRow.agent_id == agent_id)
            ):
                row.enabled = False
            session.add(
                ExternalAgentCredentialRow(
                    id=new_id("cred"),
                    agent_id=agent_id,
                    key_hash=hashlib.sha256(token.encode()).hexdigest(),
                    scopes=sorted(set(agent.scopes) | {"agent:callback", "agent:self"}),
                )
            )
        return token

    def authenticate(self, token: str) -> ExternalAgentCredentialRow | None:
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.db.session() as session:
            rows = session.scalars(
                select(ExternalAgentCredentialRow).where(ExternalAgentCredentialRow.enabled.is_(True))
            )
            return next((r for r in rows if hmac.compare_digest(r.key_hash, digest)), None)

    def routes(self) -> list[ExternalAgentRouteRow]:
        with self.db.session() as session:
            return list(session.scalars(select(ExternalAgentRouteRow).order_by(ExternalAgentRouteRow.capability)))

    def save_route(self, route: AgentRoute) -> ExternalAgentRouteRow:
        for agent_id in route.agent_ids:
            self.get(agent_id)
        with self.db.session() as session:
            row = session.get(ExternalAgentRouteRow, route.capability) or ExternalAgentRouteRow(
                capability=route.capability
            )
            row.agent_ids = route.agent_ids
            row.strategy = route.strategy
            row.enabled = route.enabled
            row.updated_at = _now()
            session.add(row)
            session.flush()
            return row

    def candidates(self, capability: str) -> tuple[list[ExternalAgentRow], str]:
        agents = {r.id: r for r in self.list(capability) if r.enabled}
        route = next((r for r in self.routes() if r.capability == capability and r.enabled), None)
        if route:
            return [agents[i] for i in route.agent_ids if i in agents], route.strategy
        return list(agents.values()), "priority"


class ExternalAgentRuntime:
    def __init__(self, db: Database, settings: Any) -> None:
        self.db = db
        self.settings = settings
        self.registry = ExternalAgentRegistry(db)
        self.secrets = SecretResolver(settings.secrets_dir, not settings.is_production())
        self._failures: dict[str, int] = {}
        self._open_until: dict[str, float] = {}
        self._semaphores: dict[str, threading.BoundedSemaphore] = {}

    def _headers(self, agent: ExternalAgentRow) -> dict[str, str]:
        auth = AgentAuth.model_validate(agent.auth or {})
        headers = {"content-type": "application/json", "x-agent-protocol": PROTOCOL_VERSION}
        if auth.type == "bearer":
            token = self.secrets.value(auth.secret_ref)
            if token:
                headers["authorization"] = f"Bearer {token}"
        elif auth.type == "workload_identity":
            token = self.secrets.value(auth.secret_ref or "file:///var/run/secrets/tokens/identity-token")
            if not token:
                raise ValueError("workload identity token is unavailable")
            headers["authorization"] = f"Bearer {token}"
        elif auth.type == "oauth2_client_credentials":
            secret = self.secrets.value(auth.secret_ref)
            if not all((auth.token_url, auth.client_id, secret)):
                raise ValueError("OAuth client credentials are incomplete")
            response = httpx.post(
                auth.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": auth.client_id,
                    "client_secret": secret,
                    "audience": auth.audience or "",
                },
                timeout=10,
            )
            response.raise_for_status()
            headers["authorization"] = f"Bearer {response.json()['access_token']}"
        return headers

    def _client(self, agent: ExternalAgentRow) -> httpx.Client:
        auth = AgentAuth.model_validate(agent.auth or {})
        verify: bool | str = self.secrets.path(auth.ca_cert_ref) or True
        cert = None
        if auth.client_cert_ref and auth.client_key_ref:
            cert = (self.secrets.path(auth.client_cert_ref), self.secrets.path(auth.client_key_ref))
        timeout = AgentLimits.model_validate(agent.limits or {}).timeout_seconds
        return httpx.Client(verify=verify, cert=cert, timeout=timeout)

    def create_invocations(self, body: DispatchRequest) -> list[ExternalAgentInvocationRow]:
        candidates, strategy = self.registry.candidates(body.capability)
        if not candidates:
            raise NotFound(f"no enabled external agent provides '{body.capability}'")
        if strategy == "priority":
            candidates = candidates[:1]
        rows: list[ExternalAgentInvocationRow] = []
        for agent in candidates:
            key = body.idempotency_key or new_id("idem")
            scoped_key = f"{agent.id}:{key}"
            request = ExecutionRequest(
                invocation_id=new_id("inv"),
                capability=body.capability,
                event=body.event,
                context=body.context,
                callback_url=f"{self.settings.public_base_url}/external-agent-invocations/{{id}}/callback",
                deadline=_now() + timedelta(seconds=AgentLimits.model_validate(agent.limits or {}).timeout_seconds),
            )
            request.callback_url = request.callback_url.replace("{id}", request.invocation_id)
            with self.db.session() as session:
                existing = session.scalar(
                    select(ExternalAgentInvocationRow).where(ExternalAgentInvocationRow.idempotency_key == scoped_key)
                )
                if existing:
                    rows.append(existing)
                    continue
                row = ExternalAgentInvocationRow(
                    id=request.invocation_id,
                    idempotency_key=scoped_key,
                    agent_id=agent.id,
                    capability=body.capability,
                    run_id=body.run_id,
                    request=request.model_dump(mode="json"),
                )
                session.add(row)
                session.flush()
                rows.append(row)
        return rows

    def list_invocations(self, limit: int = 100) -> list[ExternalAgentInvocationRow]:
        with self.db.session() as session:
            return list(
                session.scalars(
                    select(ExternalAgentInvocationRow)
                    .order_by(ExternalAgentInvocationRow.created_at.desc())
                    .limit(limit)
                )
            )

    def get_invocation(self, invocation_id: str) -> ExternalAgentInvocationRow:
        with self.db.session() as session:
            row = session.get(ExternalAgentInvocationRow, invocation_id)
            if not row:
                raise NotFound(f"external invocation {invocation_id} not found")
            return row

    def execute(self, invocation_id: str) -> ExternalAgentInvocationRow:
        invocation = self.get_invocation(invocation_id)
        if invocation.status in {"completed", "accepted"}:
            return invocation
        agent = self.registry.get(invocation.agent_id)
        limits = AgentLimits.model_validate(agent.limits or {})
        if self._open_until.get(agent.id, 0) > time.monotonic():
            raise HarnessError(f"circuit is open for {agent.name}")
        semaphore = self._semaphores.setdefault(agent.id, threading.BoundedSemaphore(limits.max_concurrency))
        if not semaphore.acquire(blocking=False):
            raise HarnessError(f"concurrency limit reached for {agent.name}")
        started = time.perf_counter()
        try:
            with self.db.session() as session:
                row = session.get(ExternalAgentInvocationRow, invocation_id)
                row.status = "running"
                row.attempts += 1
                row.updated_at = _now()
            request = ExecutionRequest.model_validate(invocation.request)
            if agent.transport == "http":
                with self._client(agent) as client:
                    response = client.post(
                        agent.endpoint,
                        json=request.model_dump(mode="json"),
                        headers=self._headers(agent),
                    )
                    response.raise_for_status()
                    result = ExecutionResult.model_validate(response.json())
            elif agent.transport == "mcp":
                payload = {
                    "jsonrpc": "2.0",
                    "id": invocation.id,
                    "method": "tools/call",
                    "params": {"name": "execute_security_agent", "arguments": request.model_dump(mode="json")},
                }
                with self._client(agent) as client:
                    response = client.post(agent.endpoint, json=payload, headers=self._headers(agent))
                    response.raise_for_status()
                    body = response.json()
                    if "error" in body:
                        raise HarnessError(str(body["error"]))
                    value = body.get("result", {}).get("structuredContent", body.get("result", {}))
                    result = ExecutionResult.model_validate(value)
            else:
                result = self._grpc(agent, request)
            with self.db.session() as session:
                row = session.get(ExternalAgentInvocationRow, invocation_id)
                row.status = result.status
                row.result = result.model_dump(mode="json")
                row.error = result.error
                row.duration_ms = (time.perf_counter() - started) * 1000
                row.updated_at = _now()
                session.flush()
                invocation = row
            self._failures[agent.id] = 0
            metrics.inc("ash_external_agent_calls_total", agent=agent.name, status=result.status)
            return invocation
        except Exception as exc:
            failures = self._failures.get(agent.id, 0) + 1
            self._failures[agent.id] = failures
            if failures >= limits.failure_threshold:
                self._open_until[agent.id] = time.monotonic() + limits.recovery_seconds
            with self.db.session() as session:
                row = session.get(ExternalAgentInvocationRow, invocation_id)
                row.status = "failed"
                row.error = str(exc)[:4000]
                row.duration_ms = (time.perf_counter() - started) * 1000
                row.updated_at = _now()
            metrics.inc("ash_external_agent_calls_total", agent=agent.name, status="failed")
            raise
        finally:
            semaphore.release()

    def _grpc(self, agent: ExternalAgentRow, request: ExecutionRequest) -> ExecutionResult:
        try:
            import grpc
        except ImportError as exc:
            raise HarnessError("install agentic-soc-harness[grpc] for gRPC agents") from exc
        auth = AgentAuth.model_validate(agent.auth or {})
        target = agent.endpoint.removeprefix("grpc://").removeprefix("grpcs://")
        if agent.endpoint.startswith("grpcs://"):
            root = Path(self.secrets.path(auth.ca_cert_ref)).read_bytes() if auth.ca_cert_ref else None
            cert = Path(self.secrets.path(auth.client_cert_ref)).read_bytes() if auth.client_cert_ref else None
            key = Path(self.secrets.path(auth.client_key_ref)).read_bytes() if auth.client_key_ref else None
            channel = grpc.secure_channel(target, grpc.ssl_channel_credentials(root, key, cert))
        else:
            channel = grpc.insecure_channel(target)
        call = channel.unary_unary(
            "/ash.agent.v1.AgentService/Execute",
            request_serializer=lambda v: v.model_dump_json().encode(),
            response_deserializer=ExecutionResult.model_validate_json,
        )
        return call(request, timeout=AgentLimits.model_validate(agent.limits or {}).timeout_seconds)

    def callback(self, invocation_id: str, body: CallbackResult, agent_id: str) -> ExternalAgentInvocationRow:
        with self.db.session() as session:
            row = session.get(ExternalAgentInvocationRow, invocation_id)
            if not row:
                raise NotFound(f"external invocation {invocation_id} not found")
            if row.agent_id != agent_id:
                raise PermissionError("credential does not own this invocation")
            row.status = body.status
            row.result = {"invocation_id": invocation_id, **body.model_dump(mode="json")}
            row.error = body.error
            row.updated_at = _now()
            session.flush()
            return row

    def health(self, agent_id: str) -> ExternalAgentRow:
        agent = self.registry.get(agent_id)
        if not agent.enabled:
            return agent
        try:
            if agent.transport == "grpc":
                raise HarnessError("use grpc.health.v1 for gRPC health checks")
            with self._client(agent) as client:
                response = client.get(agent.health_endpoint or agent.endpoint, headers=self._headers(agent))
                response.raise_for_status()
            status, error = "healthy", None
        except Exception as exc:
            status, error = "unavailable", str(exc)[:1000]
        with self.db.session() as session:
            row = session.get(ExternalAgentRow, agent_id)
            row.status = status
            row.last_error = error
            row.last_health_check = _now()
            row.updated_at = _now()
            session.flush()
            return row


def external_row(row: Any) -> dict[str, Any]:
    data = {attr.columns[0].name: getattr(row, attr.key) for attr in inspect(row).mapper.column_attrs}
    return {k: v.isoformat() if hasattr(v, "isoformat") else v for k, v in data.items()}

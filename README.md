# Agentic SOC Harness

Production-oriented orchestration and governance for security agents operating directly on an enterprise data fabric. ASH accepts SIEM and telemetry events, routes work to local or independently deployed agents, governs every model and tool action, pauses high-risk actions for human approval, and preserves durable case, run, invocation, and audit state.

This revision turns ASH into an agent plug-in runtime. An external triage, investigation, correlation, threat-intelligence, or response agent can register at runtime, advertise capabilities, receive work over HTTP, gRPC, or MCP, and submit asynchronous results without an ASH code change.

| Area | Implementation |
|---|---|
| Control plane | FastAPI, versioned REST contracts, OpenAPI at `/docs` |
| Persistence | SQLAlchemy with SQLite for development and PostgreSQL for production |
| Messaging | Redis Streams workers, retries, dead-letter stream, SQL source of truth |
| Agent protocols | Native Python, HTTP JSON, MCP `tools/call`, unary gRPC |
| Identity | Human JWT, service API keys, dynamic hashed agent credentials |
| Outbound auth | Bearer, OAuth 2.0 client credentials, workload identity, mTLS |
| Governance | RBAC, per-agent scopes, policy engine, rate limits, HITL, separation of duties |
| AI safety | Secret redaction, prompt-injection guardrail, protective-plane webhook |
| Resilience | Idempotency, timeout, concurrency limit, circuit breaker, retries, DLQ, resume state |
| Observability | Structured logs, trace/run IDs, Prometheus metrics, hash-chained audit |
| Deployment | Docker Compose, Kubernetes HA manifests, migration and DR runbooks |

## Included in this build

- Local `FunctionAgent` and `LLMAgent` contracts with resumable workflows.
- Durable external-agent registration, discovery, configuration, enablement, credentials, health, routing, dispatch, callback, and invocation APIs.
- Agent Protocol `1.0` schemas with major-version compatibility checks.
- Priority and fan-out routing by capability.
- Per-agent data-fabric scopes stored with registration and callback identity.
- HTTP, MCP, and gRPC execution adapters.
- One-time agent credentials stored only as SHA-256 hashes and independently rotatable.
- OAuth client credentials, workload identity, bearer secrets, CA trust, and client certificates using secret references.
- Redis Streams distributed workers with exponential retry and dead-letter handling.
- Idempotency keys scoped by target agent; repeated dispatch returns the original invocation.
- Per-agent timeout, maximum concurrency, failure threshold, and circuit recovery configuration.
- External-agent SDK and a runnable reference triage agent.
- SQLite/PostgreSQL persistence for cases, alerts, runs, approvals, audit records, external agents, routes, credentials, and invocations.
- Model routing for Nemotron, sovereign or other OpenAI-compatible providers, plus an offline deterministic provider.
- Connector contracts for SIEM, EDR, IAM, cloud, CMDB/assets, vulnerability/CRVM, threat intelligence, ticketing, network controls, and Remediation OS.
- Docker Compose stack with API, PostgreSQL, Redis, and worker; HA Kubernetes baseline and operations runbook.

Detailed contracts: [External Agent Protocol](docs/EXTERNAL_AGENT_PROTOCOL.md) · [Operations and DR](docs/OPERATIONS.md) · [PRD](docs/PRD.md) · [BRD](docs/BRD.md)

## Architecture

```text
 SIEM / EDR / IAM / Cloud / CMDB / VM / Threat Intel
                         |
                         v
              Shared security data fabric
                         |
                         v
  +-------------------------------------------------------------+
  | Agentic SOC Harness                                         |
  | API + AuthN/RBAC + policy + guardrails + audit              |
  |     |                         |                              |
  |     v                         v                              |
  | cases / runs / approvals   external agent registry          |
  |     |                         |                              |
  | local workflows              capability routes              |
  |     |                         |                              |
  | model + tool gateway       Redis Streams -> workers          |
  +-------------------------------|-----------------------------+
                                  v
                    HTTP / gRPC / MCP agents
                                  |
                           callback results
```

The SIEM is an event source, not the agent orchestrator. Agents are routed from the harness and retrieve only the data permitted by their registered scopes through governed tools and connector boundaries.

## Quick start

Requires Python 3.11 or newer.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
ash serve --port 8080
```

Open `http://localhost:8080/docs`. Development defaults to SQLite and inline external-agent execution. The offline model provider requires no GPU or external API.

```bash
python -m scripts.demo
pytest -q
ruff check .
```

For the production-shaped local stack:

```bash
export ASH_JWT_SECRET="$(openssl rand -hex 32)"
docker compose up --build
```

This starts PostgreSQL, Redis, the API on `http://localhost:8080`, and a distributed worker.

## External agent walkthrough

Start the reference agent:

```bash
uvicorn examples.reference_external_agent:app --port 8100
```

Authenticate as an administrator. The development bootstrap user is refused in production.

```bash
TOKEN=$(curl -s http://localhost:8080/api/v1/auth/token \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"admin"}' | \
  python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
```

Register the agent:

```bash
curl -s http://localhost:8080/api/v1/external-agents \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":"reference-triage-agent",
    "version":"1.0.0",
    "protocol_version":"1.0",
    "capabilities":["triage"],
    "transport":"http",
    "endpoint":"http://host.docker.internal:8100/execute",
    "health_endpoint":"http://host.docker.internal:8100/health",
    "scopes":["fabric:read","threat_intel:read"],
    "limits":{"timeout_seconds":15,"max_concurrency":4,"failure_threshold":3,"recovery_seconds":30}
  }'
```

The response contains a one-time `api_key`. Store it in a vault; ASH retains only its hash.

Configure deterministic routing:

```bash
curl -s -X PUT http://localhost:8080/api/v1/external-agent-routes/triage \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"capability":"triage","agent_ids":["<agent_id>"],"strategy":"priority","enabled":true}'
```

Use `fanout` to send the same event to every listed enabled agent. Each target receives a separate idempotent invocation.

Dispatch work:

```bash
curl -s http://localhost:8080/api/v1/external-agent-dispatch \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "capability":"triage",
    "event":{"id":"alert-42","severity":"high","title":"C2 beacon"},
    "context":{"tenant":"finance"},
    "idempotency_key":"alert-42:triage:v1",
    "asynchronous":true
  }'
```

With Redis configured, the API persists and queues the invocation and returns `202`; workers execute it. Without Redis, ASH executes inline for local development. Agents may return `completed` immediately or `accepted` and later POST to the supplied callback URL with `X-Agent-Key`.

## Agent SDK

```python
from ash.agents.external import ExecutionRequest, ExecutionResult
from ash.agents.sdk import ExternalAgentApplication

agent = ExternalAgentApplication("my-triage-agent", "1.0.0")

@agent.capability("triage")
def triage(request: ExecutionRequest) -> ExecutionResult:
    return ExecutionResult(
        invocation_id=request.invocation_id,
        output={"verdict": "suspicious"},
        decisions=[{"type": "triage", "confidence": 0.93}],
    )

app = agent.app
```

The SDK exposes `/execute`, `/mcp`, and `/health`. gRPC agents implement `/ash.agent.v1.AgentService/Execute` using the same versioned JSON contracts.

## Security model

Every management, discovery, dispatch, case, run, and audit route requires JWT or service API-key authentication. Public endpoints are limited to health/readiness/metrics and password token issuance. Agent callbacks require a dynamic agent credential and ownership of the invocation.

| Role | External-agent access |
|---|---|
| `viewer` | discover agents and routes |
| `soc_lead` | discover and dispatch |
| `agent_engineer` | register, configure, route, rotate, probe, and dispatch |
| `admin` | all operations |

Agent scopes are explicit strings such as `fabric:read`, `threat_intel:read`, `edr:read`, or `response:propose`. Capability names do not grant data access. Connector and tool policy remains the enforcement point for actual data operations.

Production secrets must use `env://VARIABLE` or `file:///run/secrets/name`. Literal outbound credentials and TLS paths are rejected. Put OAuth secrets, workload tokens, CA bundles, and client key pairs in the enterprise secrets manager and mount only short-lived material.

Log-derived text passes through the prompt-injection guardrail before model calls. Configure `ASH_GUARDRAIL_WEBHOOK_URL` to fail closed through AgentPEP, LLM Firewall, Thoth, or another policy enforcement point.

## Reliability semantics

- PostgreSQL is authoritative; Redis is the delivery transport.
- Redis Streams use consumer groups and at-least-once delivery.
- Idempotency is scoped to agent plus caller key.
- Immediate `completed` and delayed `accepted`/callback execution are supported.
- Worker failures retry with exponential backoff until `ASH_EXTERNAL_AGENT_MAX_ATTEMPTS`.
- Exhausted work lands in `ash:external-agent-jobs:dead-letter`.
- Per-agent bounded semaphores enforce concurrency.
- Repeated failures open a per-process circuit for the configured recovery interval.
- Existing ASH workflow and approval state is durable and resumable across nodes.

## API surface

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/external-agents` | Register agent and issue one-time credential |
| `GET /api/v1/external-agents` | Discover agents, optionally by capability |
| `GET/PATCH /api/v1/external-agents/{id}` | Inspect or configure agent |
| `POST /api/v1/external-agents/{id}/credentials` | Revoke old keys and rotate credential |
| `POST /api/v1/external-agents/{id}/health` | Execute health probe |
| `GET /api/v1/external-agent-routes` | List routes |
| `PUT /api/v1/external-agent-routes/{capability}` | Configure priority or fan-out route |
| `POST /api/v1/external-agent-dispatch` | Create and queue/execute invocations |
| `GET /api/v1/external-agent-invocations` | Invocation operations view |
| `GET /api/v1/external-agent-invocations/{id}` | Invocation detail/result |
| `POST /api/v1/external-agent-invocations/{id}/callback` | Agent-owned result submission |
| `POST /api/v1/alerts` · `/runs` · `/approvals` | Existing governed SOC lifecycle |
| `GET /health` · `/ready` · `/metrics` | Operations and Prometheus telemetry |

## Repository layout

```text
ash/agents/external.py     protocol, durable registry, executors, resilience
ash/agents/sdk.py          external agent package SDK
ash/broker.py              Redis Streams and inline transport
ash/worker.py              distributed worker and retry/DLQ loop
ash/governance/            auth, RBAC, policy, guardrails, audit
ash/persistence/           SQLAlchemy models and repository
ash/connectors/            enterprise connector contracts and references
examples/                  runnable reference external agent
migrations/                reviewed production SQL
deploy/kubernetes/         API/worker HA baseline
docs/                      PRD, BRD, protocol, operations and DR
tests/                     unit, API, governance, contract and runtime tests
```

## Production checklist

1. Use managed HA PostgreSQL and Redis with TLS, authentication, backups, and failover.
2. Apply `migrations/001_external_agent_runtime.sql` before rolling out this release.
3. Set `ASH_ENVIRONMENT=production`, a strong `ASH_JWT_SECRET`, and no bootstrap user.
4. Put human auth behind enterprise OIDC and issue narrowly scoped service identities.
5. Use workload identity or mTLS for agents; rotate any static callback keys regularly.
6. Replace reference connectors with environment-specific SIEM, SOAR, EDR, IAM, cloud, CMDB, VM, and threat-intelligence implementations.
7. Point model profiles to approved providers and enable the protective-plane webhook.
8. Scrape `/metrics`, collect JSON logs, and alert on queue age, DLQ growth, circuit openings, callback ownership failures, MTTA, false positives, override rate, and escalation accuracy.
9. Run contract, compatibility, load, and failure-injection suites against every candidate agent version.
10. Execute the restore and credential-rotation exercise in [docs/OPERATIONS.md](docs/OPERATIONS.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

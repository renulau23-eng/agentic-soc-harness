# Product Requirements Document — Agentic SOC Harness

| Field | Value |
|---|---|
| Document | PRD-ASH-001 |
| Version | 1.0 |
| Parent | BRD-ASH-001 |
| Status | Baselined for build |
| Owner | Cyber AI Centre of Excellence — Architecture |
| Date | 26 September 2026 |

---

## 1. Product vision

A **model-agnostic, governance-first runtime for security agents**. Agents describe *what* they do (system prompt, tools they may use, output contract); the harness owns *how* it happens safely (model routing, tool execution, permissions, approvals, audit, state, observability). Any agent flavour — single-shot classifier, ReAct loop, planner–executor, or a multi-agent workflow — runs on the same primitives.

Design principles:

1. **Interface over implementation.** Providers, tools, agents, connectors, stores and guardrails are all protocols with reference implementations. Nothing in the core depends on a specific vendor.
2. **Deny by default.** No tool executes without a permission and a policy decision. High-risk tools require human approval unless a policy explicitly auto-approves.
3. **Everything is evidence.** Every model call, tool call, policy decision and human decision lands in a hash-chained audit log tied to a case.
4. **Sovereign by construction.** No outbound calls except to configured inference and connector endpoints. SQLite or PostgreSQL. Runs air-gapped.
5. **Production discipline.** Typed configuration, structured logs, metrics, health checks, tests, container, CI.

---

## 2. Personas

| Persona | Needs |
|---|---|
| **Agent engineer** | Register an agent in minutes; plug in existing agent code; test offline |
| **SOC analyst (L1/L2)** | Submit alerts, watch agent progress, approve/reject actions, read explanations |
| **SOC lead / IR manager** | Configure policies, assign roles, review evidence packs |
| **Platform integrator** | Wire connectors to SIEM/EDR/TI, data fabric, CRVM, Remediation OS, protective plane |
| **Auditor / client risk** | Verify audit chain integrity, export case evidence |

---

## 3. System architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          Agentic SOC Harness                               │
│                                                                            │
│  ┌──────────────┐   ┌───────────────────────────────────────────────────┐  │
│  │  API layer   │   │  Governance plane                                 │  │
│  │  FastAPI     │──▶│  AuthN (JWT/API key) · RBAC · Policy engine ·     │  │
│  │  REST/JSON   │   │  HITL approvals · Rate limits · Guardrail hook    │  │
│  └──────────────┘   └───────────────────────────────────────────────────┘  │
│         │                                   │                              │
│         ▼                                   ▼                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌────────────┐   │
│  │ Orchestrator │──▶│ Agent runtime│──▶│ Tool registry│──▶│ Connectors │   │
│  │ workflows    │   │ loop, memory │   │ schemas, risk│   │ SIEM/EDR/TI│   │
│  └──────────────┘   └──────────────┘   └──────────────┘   │ CRVM/ROS   │   │
│                            │                              └────────────┘   │
│                            ▼                                               │
│                     ┌──────────────┐                                       │
│                     │ Model router │──▶ Nemotron (NIM/vLLM) · Sovereign ·  │
│                     │ providers    │    OpenAI-compatible · Mock (offline)  │
│                     └──────────────┘                                       │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ Persistence: cases · alerts · runs · steps · approvals · audit chain │  │
│  │ Observability: structured logs · metrics · trace IDs · health        │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Position in the CoE full-stack platform

```
Asset inventory ─▶ Inventory insights ─▶ CRVM ─▶ Remediation OS ─▶ Agentic SOC (this harness)
        └──────────────────── shared data fabric / data lake / SIEM ─────────────────┘
        └──────── protective plane: AgentPEP · LLM Firewall · Thoth (guardrail hook) ─┘
```

The harness consumes asset and vulnerability context through connectors, emits remediation requests to Remediation OS, and routes every model prompt/response and tool call through the guardrail hook so the protective plane can inspect or veto.

---

## 4. Functional requirements

### 4.1 Model providers (FR-MP)

| ID | Requirement |
|---|---|
| FR-MP-01 | `ModelProvider` protocol: `chat(messages, tools, **opts) -> ModelResponse` with native tool-call support |
| FR-MP-02 | `OpenAICompatibleProvider` for any `/v1/chat/completions` endpoint (NVIDIA NIM, vLLM, TGI, build.nvidia.com) |
| FR-MP-03 | `NemotronProvider` — thin specialisation with Nemotron defaults (reasoning toggle via system prompt `/think` `/no_think`, tool-call parsing tolerance) |
| FR-MP-04 | `SovereignProvider` — reserved slot with the same contract, configured by URL; swaps in with zero agent code change |
| FR-MP-05 | `MockProvider` — deterministic, offline, scriptable; used by CI and air-gapped smoke tests |
| FR-MP-06 | Model router: named model profiles (`reasoning`, `fast`, `sovereign`) selected per agent via config |
| FR-MP-07 | Retries with backoff, timeouts, token/latency metrics per call |

### 4.2 Agent runtime (FR-AR)

| ID | Requirement |
|---|---|
| FR-AR-01 | `Agent` protocol: `name`, `description`, `allowed_tools`, `run(ctx, input) -> AgentResult` |
| FR-AR-02 | `LLMAgent` reference implementation: system prompt + tool loop (bounded by `max_steps`), structured final output |
| FR-AR-03 | `FunctionAgent` wrapper: any Python callable becomes an agent (adapter for legacy code) |
| FR-AR-04 | Agent registry with discovery by name and capability tags |
| FR-AR-05 | Run context carries case ID, principal, trace ID, working memory, and a scratchpad persisted per step |
| FR-AR-06 | Every step (model call, tool call, approval wait) is persisted and auditable |

### 4.3 Tools (FR-TL)

| ID | Requirement |
|---|---|
| FR-TL-01 | `Tool` with name, description, JSON-schema parameters, risk tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), required permission |
| FR-TL-02 | `@tool` decorator that derives schema from a typed Python function |
| FR-TL-03 | Registry validates arguments against schema before execution |
| FR-TL-04 | Tool execution always passes through the policy engine and audit |
| FR-TL-05 | Reference SOC tools: `search_siem`, `lookup_ioc`, `get_asset`, `get_vulnerabilities`, `isolate_host`, `block_indicator`, `create_ticket`, `request_remediation` |

### 4.4 Orchestration (FR-OR)

| ID | Requirement |
|---|---|
| FR-OR-01 | `Workflow` = ordered stages; each stage names an agent and an input mapping |
| FR-OR-02 | Conditional routing on prior stage output (e.g. skip response if severity < HIGH) |
| FR-OR-03 | Workflow pauses on pending approval and resumes when decided |
| FR-OR-04 | Reference workflow `triage_investigate_respond` |

### 4.5 Governance (FR-GV)

| ID | Requirement |
|---|---|
| FR-GV-01 | AuthN: JWT bearer tokens and static API keys; principal carries roles |
| FR-GV-02 | RBAC: roles → permissions; built-ins `viewer`, `analyst`, `senior_analyst`, `soc_lead`, `admin`, `agent_engineer`, `auditor`, `service` |
| FR-GV-03 | Policy engine evaluates every tool call: allow / deny / require_approval, with rules by tool, risk tier, role, and agent |
| FR-GV-04 | HITL approval queue: create, list, approve, reject; approver must hold `approvals:decide` and cannot approve own request |
| FR-GV-05 | Audit log: append-only, SHA-256 hash-chained; `verify` endpoint checks integrity |
| FR-GV-06 | Guardrail hook: pre-model, post-model and pre-tool interceptors for AgentPEP / LLM Firewall / Thoth integration |
| FR-GV-07 | Rate limiting per principal |
| FR-GV-08 | Secrets only via environment; no secrets in logs |

### 4.6 Case management (FR-CM)

| ID | Requirement |
|---|---|
| FR-CM-01 | Alerts ingested via API become cases (or attach to existing cases) |
| FR-CM-02 | Case states: `NEW → TRIAGED → INVESTIGATING → AWAITING_APPROVAL → CONTAINED → RESOLVED → CLOSED` (+ `FALSE_POSITIVE`) |
| FR-CM-03 | Case timeline aggregates runs, steps, approvals and audit entries |
| FR-CM-04 | Evidence pack export (JSON) for a case |

### 4.7 Connectors (FR-CN)

| ID | Requirement |
|---|---|
| FR-CN-01 | Protocols: `SIEMConnector`, `EDRConnector`, `ThreatIntelConnector`, `TicketingConnector`, `AssetConnector`, `VulnerabilityConnector`, `RemediationConnector` |
| FR-CN-02 | In-memory reference implementations for all, used by tools and tests |
| FR-CN-03 | Connector selection by config; concrete client connectors delivered per engagement |

### 4.8 API (FR-API)

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/auth/token` | Issue JWT for a user |
| `GET /api/v1/agents` | List registered agents |
| `GET /api/v1/tools` | List tools with risk tier and permission |
| `POST /api/v1/alerts` | Ingest alert → creates case |
| `GET /api/v1/cases`, `GET /api/v1/cases/{id}` | Case listing and detail |
| `GET /api/v1/cases/{id}/evidence` | Evidence pack |
| `POST /api/v1/runs` | Run an agent or workflow against a case |
| `GET /api/v1/runs/{id}` | Run status and steps |
| `POST /api/v1/runs/{id}/resume` | Resume after approval |
| `GET /api/v1/approvals` | Pending approvals |
| `POST /api/v1/approvals/{id}/decide` | Approve or reject |
| `GET /api/v1/audit`, `GET /api/v1/audit/verify` | Audit entries and chain verification |
| `GET /health`, `GET /ready`, `GET /metrics` | Operations |

### 4.9 Observability (FR-OB)

- Structured JSON logs with `trace_id`, `case_id`, `run_id`, `principal`.
- Metrics: model calls, tokens, latency, tool calls by tier, approvals, errors.
- Health and readiness endpoints; readiness checks DB and configured providers.

---

## 5. Non-functional requirements

| Area | Requirement |
|---|---|
| Security | Deny-by-default tools; secrets via env; JWT with expiry; input validation on all endpoints; no eval of model output |
| Sovereignty | No external calls except configured endpoints; runs offline with `MockProvider` |
| Reliability | Bounded agent loops; retries with backoff; idempotent approval decisions; DB transactions |
| Performance | Async I/O; ≥ 50 concurrent runs on a single node with local inference |
| Portability | Python 3.11+; SQLite/PostgreSQL; Docker; no OS-specific code |
| Testability | Offline test suite; ≥ 80% coverage of core modules |
| Maintainability | Typed models (Pydantic), protocols, single config surface |

---

## 6. Data model

| Entity | Key fields |
|---|---|
| `Principal` | id, roles, type (user/service/agent) |
| `Alert` | id, source, title, severity, raw, received_at, case_id |
| `Case` | id, title, severity, status, created_by, timestamps |
| `Run` | id, case_id, agent/workflow, status, input, output, principal, trace_id |
| `Step` | id, run_id, seq, type (model/tool/approval/note), payload, result, duration |
| `Approval` | id, run_id, tool, args, risk_tier, requested_by, status, decided_by, decided_at, reason |
| `AuditEntry` | seq, timestamp, actor, action, target, detail, prev_hash, hash |

---

## 7. Configuration

Single `Settings` object (Pydantic settings) sourced from environment / `.env`, with optional YAML for model profiles, roles and policies.

Key settings: `ASH_DATABASE_URL`, `ASH_JWT_SECRET`, `ASH_API_KEYS`, `ASH_MODEL_PROFILE_DEFAULT`, `ASH_MODEL_<PROFILE>_PROVIDER`, `ASH_MODEL_<PROFILE>_BASE_URL`, `ASH_MODEL_<PROFILE>_MODEL`, `ASH_MODEL_<PROFILE>_API_KEY`, `ASH_POLICY_FILE`, `ASH_LOG_LEVEL`.

Example — Nemotron via local NIM:

```
ASH_MODEL_REASONING_PROVIDER=nemotron
ASH_MODEL_REASONING_BASE_URL=http://nim.soc.local:8000/v1
ASH_MODEL_REASONING_MODEL=nvidia/nemotron-3-super-120b-a12b
```

Example — sovereign model later:

```
ASH_MODEL_REASONING_PROVIDER=sovereign
ASH_MODEL_REASONING_BASE_URL=http://sovereign.soc.local:8000/v1
ASH_MODEL_REASONING_MODEL=ey-sovereign-7b-soc
```

---

## 8. Acceptance criteria

1. `pytest` passes offline with no network.
2. A demo alert runs through `triage_investigate_respond`, pauses for approval on `isolate_host`, resumes after a `soc_lead` approves, and produces a resolved case with a verifiable audit chain.
3. Switching `ASH_MODEL_REASONING_PROVIDER` between `mock`, `nemotron`, `openai_compatible`, `sovereign` requires no code change.
4. A `viewer` cannot run agents or approve; an `analyst` cannot approve their own request; an `auditor` can verify the audit chain.
5. `docker compose up` brings up the API with health green.

---

## 9. Release plan

| Phase | Content |
|---|---|
| R1 (this build) | Core runtime, governance, API, reference tools/connectors/workflow, tests, container, CI |
| R2 | Client connector packs (SIEM/EDR/TI), Langfuse/OTel exporter, UI |
| R3 | Bead-Memory attack-chain correlation module, evaluation harness integration, sovereign model adapter tuning |

# Agentic SOC Harness (ASH)

**A model-agnostic, governance-first runtime for security agents.**
Any SOC agent — existing, new, in-house, or fine-tuned on a sovereign model — plugs into the harness and inherits model routing, tool governance, RBAC, human-in-the-loop approvals, a tamper-evident audit chain, case management and observability. Nothing about the agent's logic needs to change when the model changes.

Built for the Cyber AI CoE full-stack platform (asset inventory → inventory insights → CRVM → Remediation OS → agentic SOC, on a shared data fabric / SIEM / data lake, protected by AgentPEP · LLM Firewall · Thoth). Runs fully on-prem and air-gapped.

| | |
|---|---|
| Documents | [BRD](docs/BRD.md) · [PRD](docs/PRD.md) |
| Runtime | Python 3.11+, FastAPI, SQLAlchemy (SQLite / PostgreSQL) |
| Models | **NVIDIA Nemotron family** (NIM, vLLM, build.nvidia.com), any OpenAI-compatible endpoint, **sovereign model slot**, offline deterministic playbook model |
| Governance | JWT + API keys · RBAC · policy engine · HITL approvals with separation of duties · SHA-256 hash-chained audit · guardrail hook · rate limits |
| Quality | 54 tests, 91% coverage, ruff-clean, Dockerfile, docker-compose, GitHub Actions (SQLite, PostgreSQL, container smoke) |

---

## 60-second tour

```bash
pip install -e ".[dev]"
pytest -q                 # 54 passed — fully offline
python -m scripts.demo    # incident end to end with the offline playbook model
```

The demo ingests a C2-beaconing alert, runs `triage → investigate → respond`, **pauses** when the response agent wants to `isolate_host` (HIGH tier), refuses the analyst's attempt to approve her own request, lets a SOC lead approve, resumes, gates `block_indicator` the same way, raises a ticket, marks the case `contained`, and finally verifies the audit chain — 34 hash-linked entries.

Start the API:

```bash
cp .env.example .env
ash serve --port 8080          # http://localhost:8080/docs
```

```bash
TOKEN=$(curl -s localhost:8080/api/v1/auth/token -d '{"username":"admin","password":"admin"}' \
        -H 'content-type: application/json' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s localhost:8080/api/v1/alerts -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d '{"source":"siem","title":"C2 beacon","severity":"high","indicators":["185.220.101.45"],"asset_id":"host-fin-042"}'
curl -s localhost:8080/api/v1/runs -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d '{"target":"triage_investigate_respond","case_id":"<case_id>"}'
curl -s localhost:8080/api/v1/approvals -H "Authorization: Bearer $TOKEN"
curl -s localhost:8080/api/v1/approvals/<approval_id>/decide -H "Authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' -d '{"approve":true,"note":"confirmed C2"}'
curl -s localhost:8080/api/v1/audit/verify -H "Authorization: Bearer $TOKEN"
```

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          Agentic SOC Harness                               │
│  ┌──────────────┐   ┌───────────────────────────────────────────────────┐  │
│  │  API layer   │   │  Governance plane                                 │  │
│  │  FastAPI     │──▶│  AuthN (JWT/API key) · RBAC · Policy engine ·     │  │
│  │  REST/JSON   │   │  HITL approvals · Rate limits · Guardrail hook    │  │
│  └──────────────┘   └───────────────────────────────────────────────────┘  │
│         ▼                                   ▼                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌────────────┐   │
│  │ Orchestrator │──▶│ Agent runtime│──▶│ Tool registry│──▶│ Connectors │   │
│  │ workflows    │   │ loop, state  │   │ schemas, risk│   │ SIEM/EDR/TI│   │
│  └──────────────┘   └──────────────┘   └──────────────┘   │ CRVM/ROS   │   │
│                            ▼                              └────────────┘   │
│                     ┌──────────────┐                                       │
│                     │ Model router │──▶ Nemotron (NIM/vLLM) · Sovereign ·  │
│                     │ profiles     │    OpenAI-compatible · Mock (offline)  │
│                     └──────────────┘                                       │
│  Persistence: cases · alerts · runs · steps · approvals · audit chain      │
│  Observability: JSON logs w/ trace ids · Prometheus /metrics · /health     │
└────────────────────────────────────────────────────────────────────────────┘
```

### Every tool call goes through the same gate

```
agent → ctx.call_tool(name, args)
   1. tool exists?  in the agent's allow-list?          → else denied (returned to the agent as a tool error)
   2. JSON-schema validation & coercion                  → else denied
   3. guardrail chain  before_tool  (AgentPEP/Thoth hook) → may mutate or block
   4. policy engine:  explicit rules → RBAC gate → tier defaults
        ALLOW              → execute, record step, audit
        REQUIRE_APPROVAL   → persist approval + run state, park run (AWAITING_APPROVAL)
        DENY               → tool error back to the agent, audited
   5. human decides (approvals:decide, not the requester, must hold the tier permission)
        approve → tool executes under the approver's authority → run resumes with the result
        reject  → run resumes with "rejected by human approver (<note>)" as the tool result
```

Risk tiers: `low` (read-only) · `medium` (tickets, remediation requests) · `high` (isolate, block) · `critical` (release from isolation). Defaults: low/medium allow, high/critical require approval. A principal without the tier permission is **escalated to an authorised approver, not silently denied** — the agent proposes, a human disposes.

---

## Package layout

```
ash/
  core/            types (Message, ToolCall, RiskTier, CaseStatus, …) and errors
  config.py        typed Settings (env / .env / YAML), dynamic model profiles
  observability.py JSON logging with context, Prometheus-text metrics
  providers/       ModelProvider protocol · OpenAI-compatible · Nemotron · Sovereign · Mock/playbook · router
  tools/           @tool decorator, schema derivation/validation, registry, reference SOC tool pack
  connectors/      protocols for SIEM/EDR/TI/ticketing/assets/CRVM/Remediation OS/network + in-memory refs
  agents/          Agent protocol, RunContext, LLMAgent (resumable tool loop), FunctionAgent (legacy adapter), registry, reference SOC agents
  orchestration/   Workflow / Stage with conditional routing, resumable across approvals
  governance/      auth (JWT/PBKDF2/API keys), RBAC, policy engine, approvals, hash-chained audit, guardrails, rate limit
  persistence/     SQLAlchemy models + repository (SQLite / PostgreSQL)
  runtime.py       Harness — wires everything; the one place governance is enforced
  api.py           FastAPI app
  cli.py           ash serve | demo | hash-password | verify-audit
config/            policy.yaml, models.example.yaml, users.example.yaml
scripts/           demo.py (offline e2e), demo_pg.py (PostgreSQL CI)
tests/             unit · harness integration · API
docs/              BRD.md · PRD.md
```

---

## Plugging in your agents

### 1. An LLM agent (prompt + tool allow-list)

```python
from ash.agents import LLMAgent
from ash.runtime import Harness

hz = Harness.build()
hz.agents.register(LLMAgent(
    name="hunting",
    description="Hypothesis-driven threat hunting over SIEM data.",
    system_prompt="You are the Hunting agent ...",
    allowed_tools=["search_siem", "lookup_ioc", "get_asset"],
    model_profile="reasoning",          # any profile from config — Nemotron today, sovereign tomorrow
))
```

### 2. Existing agent code (v3 / HAL-O) — wrap it, keep it

```python
from ash.agents import agent
from ash.core.types import AgentResult, ToolCall

@agent("legacy_forensics", allowed_tools=["search_siem", "get_host_status"])
def legacy_forensics(ctx, input):
    hits = ctx.call_tool(ToolCall(name="search_siem", arguments={"query": f"host:{input['alert']['asset_id']}"}))
    ...  # your existing logic
    return AgentResult(output={...}, summary="...", severity=..., next_status=...)
```

Wrapped agents get RBAC, policy, approvals and audit for free. If a wrapped agent hits an approval gate it re-runs from scratch on resume; the harness serves the human decision for the matching tool+arguments, so the agent sees the approved (or rejected) result exactly as if the tool had returned it. `LLMAgent` is fully resumable (its transcript is persisted) and continues in place.

### 3. Any other flavour

Implement the `Agent` protocol (`name`, `description`, `allowed_tools`, `tags`, `run(ctx, input) -> AgentResult`). Planner–executor, ReAct, multi-agent debate, classifier — the harness does not care, as long as models and tools are reached through `ctx.chat()` and `ctx.call_tool()`.

### 4. New tools

```python
from ash.tools import tool
from ash.core.types import RiskTier

@tool(risk_tier=RiskTier.HIGH, tags=["iam"])
def disable_user(ctx, user_id: str, reason: str) -> dict:
    """Disable an identity in the IdP."""
    return ctx.connectors.idp.disable(user_id, reason)

hz.tools.register(disable_user)
```

Schema, permission (`tools:execute:high`) and approval behaviour follow from the tier.

### 5. Workflows

```python
from ash.orchestration import Workflow, Stage

hz.workflows.register(Workflow(
    name="phishing",
    description="Phishing triage and response",
    stages=[
        Stage("triage", agent="triage"),
        Stage("hunt", agent="hunting", when=lambda out: out["triage"].get("verdict") == "true_positive"),
        Stage("respond", agent="respond", when=lambda out: out["hunt"].get("_severity") in {"high", "critical"}),
    ],
))
```

---

## Models: Nemotron today, sovereign tomorrow

Agents name a **profile**; operators decide what serves it. All providers speak the OpenAI `/v1/chat/completions` contract, so NVIDIA NIM, vLLM, TGI, llama.cpp-server or the CoE sovereign inference service all work without code changes.

```bash
# Nemotron 3 Super on a local NIM (air-gapped)
ASH_MODEL_REASONING_PROVIDER=nemotron
ASH_MODEL_REASONING_BASE_URL=http://nim.soc.local:8000/v1
ASH_MODEL_REASONING_MODEL=nvidia/nemotron-3-super-120b-a12b
ASH_MODEL_REASONING_REASONING=true      # /think toggle injected into the system prompt

# CoE Nemotron-30B SOC LoRA build, or the ground-up Sovereign 7B — same slot
ASH_MODEL_REASONING_PROVIDER=sovereign
ASH_MODEL_REASONING_BASE_URL=http://sovereign.soc.local:8000/v1
ASH_MODEL_REASONING_MODEL=coe/sovereign-7b-soc
```

`NemotronProvider` handles the Nemotron conventions: `/think` / `/no_think` reasoning toggle, `<think>` and `reasoning_content` lifted out of the answer, and text-encoded `<tool_call>` blocks parsed when the server has no native tool parser. `SovereignProvider` is the reserved slot for CoE models (fixed system preamble for adapter-trained builds; extend as the tokenizer/format matures). Additional profiles (`fast`, `soc_adapter`, …) can be defined in `config/models.example.yaml`; a custom provider kind is registered with `register_provider()`.

The offline `mock` provider (`soc-playbook`) is a deterministic rule-based stand-in that drives the reference workflow through real tool calls, so the *harness* is tested independently of model quality — CI needs no GPU.

---

## Governance details

**Roles** (default; extend in `policy.yaml`): `viewer`, `analyst` (run agents, low/medium tools), `senior_analyst` (+ decide approvals, high tools), `soc_lead` (+ all tiers, audit read), `agent_engineer`, `auditor` (audit read/verify), `service` (ingest + run), `admin`.

**Approvals**: separation of duties (requester ≠ approver), approver must hold the tool's tier permission, idempotent decisions, TTL expiry, approved tools execute under the approver's authority and are audited as such. A run parked on approval is durable — a different process (or node) can decide and resume it.

**Audit**: every case/alert/run/model call/policy decision/tool execution/approval/status change is an entry with `hash = SHA-256(prev_hash ‖ canonical JSON)`. `GET /api/v1/audit/verify` walks the chain and reports the first broken link; `GET /api/v1/cases/{id}/evidence` bundles case, alerts, runs with steps, approvals, audit entries and the chain status into one JSON evidence pack.

**Guardrail hook**: `before_model`, `after_model`, `before_tool`. Reference chain: secret redaction + prompt-injection heuristic. Set `ASH_GUARDRAIL_WEBHOOK_URL` to route all three stages to AgentPEP / LLM Firewall / Thoth (`POST {stage, payload, meta}` → `{allow, reason, payload}`; fails closed).

**Sovereignty**: no outbound calls except configured inference and connector endpoints; SQLite or PostgreSQL; runs air-gapped; secrets only via environment and never logged.

---

## API

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/auth/token` · `GET /api/v1/auth/me` | JWT login; who am I + effective permissions |
| `GET /api/v1/agents` · `/workflows` · `/tools` · `/models` | Catalog |
| `POST /api/v1/alerts` | Ingest alert → case |
| `GET /api/v1/cases` · `GET /api/v1/cases/{id}` · `POST …/status` · `GET …/evidence` | Cases |
| `POST /api/v1/runs` · `GET /api/v1/runs/{id}` · `POST …/resume` | Runs (agent or workflow) |
| `GET /api/v1/approvals` · `POST /api/v1/approvals/{id}/decide` | Human-in-the-loop |
| `GET /api/v1/audit` · `GET /api/v1/audit/verify` | Audit |
| `GET /health` · `GET /ready` · `GET /metrics` | Ops (Prometheus text format) |

Interactive docs at `/docs`. Auth via `Authorization: Bearer <jwt>` or `X-API-Key: <key>` (service accounts, e.g. SIEM ingestion).

---

## Deployment

```bash
# container
docker build -t agentic-soc-harness .
docker run -p 8080:8080 -e ASH_JWT_SECRET=$(openssl rand -hex 32) -e ASH_MODEL_REASONING_PROVIDER=mock agentic-soc-harness

# API + PostgreSQL
ASH_JWT_SECRET=$(openssl rand -hex 32) docker compose up --build
```

Production checklist: set `ASH_ENVIRONMENT=production` (refuses default JWT secret and bootstrap admin), PostgreSQL via `ASH_DATABASE_URL`, users from `ASH_USERS_FILE` or an IdP in front of the API, real `ASH_API_KEYS`, `ASH_POLICY_FILE`, point model profiles at your NIM/vLLM, set `ASH_GUARDRAIL_WEBHOOK_URL` to the protective plane, scrape `/metrics`, ship JSON logs.

---

## Development

```bash
make install   # deps
make test      # pytest + coverage
make lint      # ruff
make demo      # offline incident
```

CI runs lint, tests (Python 3.11/3.12, coverage gate 85%), the offline demo, the PostgreSQL demo and a container smoke test.

---

## Roadmap (from the PRD)

- **R2** — client connector packs (SIEM/EDR/TI), Langfuse/OTel exporter, UI, async run execution with a queue.
- **R3** — Bead-Memory attack-chain correlation module, evaluation-harness integration, sovereign-model adapter tuning.

Licensed under Apache-2.0.

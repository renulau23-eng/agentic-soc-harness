# Business Requirements Document — Agentic SOC Harness

| Field | Value |
|---|---|
| Document | BRD-ASH-001 |
| Version | 1.0 |
| Status | Baselined for build |
| Owner | Cyber AI Centre of Excellence — Architecture |
| Date | 26 September 2026 |
| Classification | Internal — client-shareable on request |

---

## 1. Executive summary

The Cyber AI CoE has built multiple generations of agentic SOC capability: the v3 platform (Detection, Triage, Threat Intel, IR, Forensics, Compliance, Response, Hunting, Orchestrator agents), the twelve-workflow HAL-O platform, and a set of eleven agents fine-tuned on the Nemotron model stack that now serve as the reference build for sovereign LLM offers. Each generation re-implemented the same plumbing — model connectivity, tool calling, approvals, access control, audit, case state — in slightly different ways.

The **Agentic SOC Harness** is a single, production-grade runtime that owns that plumbing once. Any SOC agent — existing, new, in-house, partner-built, or fine-tuned on a sovereign model — plugs into the harness and inherits model routing, tool governance, role-based access control, human-in-the-loop approval, tamper-evident audit, case management, and observability without re-implementing them.

The business outcome is a **standard, defensible, sovereign-deployable foundation** that shortens every future SOC agent build, satisfies regulator and client due-diligence on AI governance, and sits cleanly inside the CoE's full-stack cyber platform (asset inventory → inventory insights → CRVM → Remediation OS → agentic SOC on a shared data fabric, SIEM and data lake, protected by AgentPEP, LLM Firewall and Thoth).

---

## 2. Business context

### 2.1 Problem statement

1. **Duplicated infrastructure.** Every agentic SOC effort re-builds model adapters, tool loops, approval flows and RBAC. Estimated 40–60% of agent-build effort is harness, not SOC logic.
2. **Inconsistent governance.** Approval gates, permission checks and audit trails differ per build, which is unacceptable for regulated clients (BFSI under RBI, critical infrastructure under CERT-In, personal-data processors under DPDPA) and for defence-grade engagements.
3. **Model lock-in risk.** Existing builds are wired to specific model endpoints. The CoE's strategy is Nemotron-family today (30B with SOC LoRA adapters; Nemotron 3 Super 120B-A12B evaluation) and a ground-up Sovereign 7B tomorrow. The runtime must switch models without touching agent code.
4. **Prototype credibility gap.** Client and management reviews have repeatedly challenged prototype-quality code. The harness must be demonstrably production-grade: tested, containerised, configurable, observable, and safe by default.
5. **Codebase access friction.** Internal disputes over access to earlier SOC code slow fine-tuning and integration work. A clean, self-contained harness with clear interfaces reduces dependence on any single legacy codebase.

### 2.2 Strategic alignment

| CoE pillar | How the harness serves it |
|---|---|
| **AI for Cyber** — agentic SOC, sovereign LLMs, vulnerability management | Runtime for all SOC agents; native model-provider abstraction for Nemotron and sovereign models; integration seams to Remediation OS and CRVM |
| **Cyber for AI** — LLM security, AI governance, agent policy enforcement | Built-in policy engine, tool allow-lists, HITL gates, immutable audit, and a protective-plane hook point for AgentPEP / LLM Firewall / Thoth |
| **Sovereignty** | Zero mandatory external dependencies at runtime; runs air-gapped on-prem with SQLite or PostgreSQL and any OpenAI-compatible local inference server (NIM, vLLM, TGI) |

---

## 3. Business objectives and success criteria

| # | Objective | Measure | Target |
|---|---|---|---|
| BO-1 | Cut time-to-first-working-agent for new SOC use cases | Engineering days from spec to a governed, testable agent | ≤ 3 days (from ~3 weeks) |
| BO-2 | Single governance surface for all agents | % of agent actions covered by RBAC + audit | 100% |
| BO-3 | Model portability | Effort to swap reasoning model (Nemotron ↔ sovereign ↔ other) | Configuration change only, zero code change |
| BO-4 | Client/regulator defensibility | Evidence pack (audit chain, approval records, test report) producible on demand | Available via API for any case |
| BO-5 | Sovereign deployability | Runs fully air-gapped with no SaaS calls | Verified in test |
| BO-6 | Production quality | Automated test suite, containerised build, CI pipeline | All green on every commit |

---

## 4. Scope

### 4.1 In scope

- Universal agent runtime: register any agent (any "flavour" — reasoning, ReAct, planner–executor, single-shot classifier, multi-agent workflow) behind one interface.
- Model provider abstraction with first-class support for Nemotron-family models over NVIDIA NIM / vLLM / any OpenAI-compatible endpoint, plus a sovereign-model slot and an offline deterministic provider for tests and air-gapped smoke checks.
- Tool registry with schema validation, risk tiers, and per-role permissions.
- Workflow orchestration: sequential and conditional multi-agent pipelines (e.g. Triage → Investigate → Respond).
- Governance: authentication (JWT + API keys), RBAC, policy engine, human-in-the-loop approval queue, hash-chained audit log, rate limits.
- Case and alert lifecycle management with persistent state.
- Connector interfaces for SIEM, EDR, threat intelligence, ticketing, and the CoE full-stack platform (asset inventory, CRVM, Remediation OS), with reference/mock implementations.
- Observability: structured JSON logs, Prometheus-style metrics, trace IDs, health endpoints.
- Deployment: Docker image, docker-compose, environment/YAML configuration, CI workflow.
- Full test suite and documentation (BRD, PRD, README, API reference).

### 4.2 Out of scope (this release)

- Model training or fine-tuning pipelines (covered by the Nemotron fine-tuning playbook).
- SIEM/EDR product-specific connectors beyond reference implementations (delivered per engagement).
- Web UI (the harness exposes an API; UI is a separate front-end workstream).
- Multi-tenant SaaS billing.
- Replacement of AgentPEP / LLM Firewall / Thoth (the harness integrates with them via a guardrail hook; it does not re-implement them).

---

## 5. Stakeholders

| Stakeholder | Role | Interest |
|---|---|---|
| CoE leadership / senior partner | Sponsor | Defensible, client-ready platform; sovereignty story |
| Agentic SOC engineering team | Primary users (builders) | Fast onboarding of existing agents; clear extension points |
| SOC analysts (L1–L3) | End users via API/UI | Reliable triage, approvals they can trust, explainable actions |
| Client CISO / risk / audit | Assurance | RBAC, HITL, audit evidence, data residency |
| Sovereign LLM workstream | Supplier | Drop-in slot for Nemotron LoRA and Sovereign 7B models |
| Full-stack platform workstream | Integrator | Clean contracts to data fabric, CRVM, Remediation OS, protective plane |

---

## 6. Business requirements

| ID | Requirement | Priority |
|---|---|---|
| BR-01 | Any SOC agent must be runnable inside the harness without changing the harness code | Must |
| BR-02 | Reasoning/tool-calling model must be swappable via configuration, with Nemotron-family models supported out of the box and a slot reserved for the CoE sovereign model | Must |
| BR-03 | Every agent action, tool call, model call and human decision must be recorded in a tamper-evident audit trail | Must |
| BR-04 | High-impact actions (containment, blocking, ticket closure, external notifications) must require human approval unless explicitly auto-approved by policy | Must |
| BR-05 | Access to agents, tools, cases and approvals must be governed by role-based access control | Must |
| BR-06 | The harness must run fully on-premises and air-gapped with no external SaaS dependency | Must |
| BR-07 | The harness must expose integration points to the CoE full-stack platform and protective plane | Must |
| BR-08 | The harness must be production quality: automated tests, containerised, configurable, observable, documented | Must |
| BR-09 | The harness must support multi-agent workflows composed from registered agents | Should |
| BR-10 | The harness must provide a client-shareable evidence pack (case timeline + approvals + audit chain) via API | Should |
| BR-11 | The harness must be extensible to non-SOC security agents (vulnerability management, privacy scanning) using the same primitives | Could |

---

## 7. Constraints and assumptions

- Python 3.11+ runtime; PostgreSQL for production, SQLite for development/tests.
- Inference served by OpenAI-compatible endpoints (NVIDIA NIM, vLLM, TGI) — the industry-standard contract, so no proprietary SDK is required at runtime.
- On-prem GPU footprint per the sovereign LLM workstream (H100 PCIe node today; DGX-class for larger models).
- Alignment to CERT-In incident reporting timelines, DPDPA data-handling principles, and RBI cyber-resilience expectations is achieved through configuration and audit, not hard-coded to any one regulator.

---

## 8. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Model behaviour drift between Nemotron variants and sovereign model | Agent quality regression | Provider abstraction + deterministic evaluation harness + offline provider in CI |
| Over-automation without approvals | Operational/regulatory harm | Risk-tiered tools; HITL mandatory for tier ≥ HIGH by default |
| Legacy agent code coupling | Slow migration | Adapter pattern: legacy agents wrapped as `Agent` implementations |
| Codebase access disputes | Delivery delay | Harness is standalone; legacy code is optional |

---

## 9. Benefits

- One governed runtime replacing per-project plumbing.
- Immediate client-facing proof of AI governance (RBAC, HITL, audit) — directly answers due-diligence questionnaires.
- Model sovereignty path from Nemotron today to Sovereign 7B without re-platforming.
- Reusable across the CoE product line (HAL-O, Remediation OS agents, privacy scanner agents).

---

## 10. Approval

| Role | Name | Decision |
|---|---|---|
| Architecture lead | — | Approved for build |
| CoE leadership | — | Pending review |

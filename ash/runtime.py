"""The Harness: the single runtime every agent runs inside.

Responsibilities
* Build and hold all components (router, tools, agents, workflows, governance, persistence).
* Execute runs: agent or workflow, synchronous, resumable.
* Enforce governance on every model call (guardrails) and tool call
  (allow-list → schema → guardrails → RBAC/policy → approval → execute → audit).
* Manage cases and human approvals.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from ash.agents.base import RunContext
from ash.agents.external import ExternalAgentRuntime
from ash.agents.registry import AgentRegistry
from ash.agents.soc import soc_agents
from ash.broker import create_broker
from ash.config import Settings, get_settings
from ash.connectors.base import Connectors
from ash.connectors.memory import memory_connectors
from ash.core.errors import (
    ApprovalRequired,
    AuthorizationError,
    GuardrailBlocked,
    HarnessError,
    NotFound,
    ToolValidationError,
)
from ash.core.types import (
    AgentResult,
    AlertIn,
    ApprovalStatus,
    CaseStatus,
    Message,
    ModelResponse,
    PolicyDecision,
    Principal,
    RunStatus,
    StepType,
    ToolCall,
    ToolResult,
    ToolSpec,
    new_id,
)
from ash.governance.audit import AuditLog
from ash.governance.auth import AuthService
from ash.governance.guardrails import (
    GuardrailChain,
    PromptInjectionGuardrail,
    SecretRedactionGuardrail,
    WebhookGuardrail,
)
from ash.governance.policy import PolicyConfig, PolicyEngine
from ash.governance.ratelimit import RateLimiter
from ash.governance.rbac import (
    P_AGENTS_RUN,
    P_ALERTS_INGEST,
    P_APPROVALS_DECIDE,
    P_APPROVALS_READ,
    P_AUDIT_READ,
    P_AUDIT_VERIFY,
    P_CASES_READ,
    P_CASES_WRITE,
    RBAC,
)
from ash.observability import configure_logging, get_logger, log_context, metrics
from ash.orchestration.workflow import WorkflowRegistry, triage_investigate_respond
from ash.persistence.models import ApprovalRow, CaseRow, RunRow
from ash.persistence.repository import Database, Repository
from ash.providers.router import ModelRouter
from ash.tools.base import ToolRegistry
from ash.tools.soc import ToolContext, soc_tools

log = get_logger(__name__)


class Harness:
    def __init__(
        self,
        *,
        settings: Settings,
        db: Database,
        router: ModelRouter,
        tools: ToolRegistry,
        agents: AgentRegistry,
        workflows: WorkflowRegistry,
        connectors: Connectors,
        rbac: RBAC,
        policy: PolicyEngine,
        guardrails: GuardrailChain,
        auth: AuthService,
    ):
        self.settings = settings
        self.db = db
        self.repo = Repository(db)
        self.audit = AuditLog(self.repo)
        self.router = router
        self.tools = tools
        self.agents = agents
        self.workflows = workflows
        self.connectors = connectors
        self.rbac = rbac
        self.policy = policy
        self.guardrails = guardrails
        self.auth = auth
        self.ratelimiter = RateLimiter(settings.rate_limit_per_minute)
        self.external_agents = ExternalAgentRuntime(db, settings)
        self.broker = create_broker(settings.broker_url)
        self._run_locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    # ------------------------------------------------------------------ #
    # construction
    # ------------------------------------------------------------------ #
    @classmethod
    def build(
        cls,
        settings: Settings | None = None,
        *,
        connectors: Connectors | None = None,
        include_reference_pack: bool = True,
        guardrails: list[Any] | None = None,
    ) -> Harness:
        settings = settings or get_settings()
        settings.validate_for_environment()
        configure_logging(settings.log_level, settings.log_json)

        db = Database(settings.database_url)
        db.create_all()

        router = ModelRouter.from_settings(settings)
        rbac = RBAC()
        policy_cfg = PolicyConfig.from_yaml(settings.policy_file) if settings.policy_file else PolicyConfig()
        policy = PolicyEngine(rbac, policy_cfg)

        chain_items: list[Any] = (
            list(guardrails)
            if guardrails is not None
            else [SecretRedactionGuardrail(), PromptInjectionGuardrail(block=False)]
        )
        if settings.guardrail_webhook_url:
            chain_items.append(WebhookGuardrail(settings.guardrail_webhook_url))

        tools = ToolRegistry()
        agents = AgentRegistry()
        workflows = WorkflowRegistry()
        if include_reference_pack:
            tools.register_many(soc_tools())
            agents.register_many(soc_agents())
            workflows.register(triage_investigate_respond())

        return cls(
            settings=settings,
            db=db,
            router=router,
            tools=tools,
            agents=agents,
            workflows=workflows,
            connectors=connectors or memory_connectors(),
            rbac=rbac,
            policy=policy,
            guardrails=GuardrailChain(chain_items),
            auth=AuthService(settings),
        )

    # ------------------------------------------------------------------ #
    # cases & alerts
    # ------------------------------------------------------------------ #
    def ingest_alert(self, alert: AlertIn, principal: Principal) -> tuple[CaseRow, str]:
        self.rbac.require(principal, P_ALERTS_INGEST)
        if alert.case_id:
            case = self.repo.get_case(alert.case_id)
        else:
            case = self.repo.create_case(
                title=alert.title,
                severity=alert.severity.value,
                created_by=principal.id,
                context={"source": alert.source, "asset_id": alert.asset_id, "indicators": alert.indicators},
            )
            self.audit.record(
                actor=principal.id,
                action="case.created",
                target=case.id,
                case_id=case.id,
                detail={"title": alert.title, "severity": alert.severity.value},
            )
        row = self.repo.add_alert(
            case_id=case.id,
            source=alert.source,
            title=alert.title,
            severity=alert.severity.value,
            payload=alert.model_dump(mode="json"),
        )
        self.audit.record(
            actor=principal.id,
            action="alert.ingested",
            target=row.id,
            case_id=case.id,
            detail={"source": alert.source, "severity": alert.severity.value},
        )
        metrics.inc("ash_alerts_ingested_total", source=alert.source)
        return case, row.id

    def get_case(self, case_id: str, principal: Principal) -> CaseRow:
        self.rbac.require(principal, P_CASES_READ)
        return self.repo.get_case(case_id)

    def list_cases(self, principal: Principal, status: str | None = None, limit: int = 100) -> list[CaseRow]:
        self.rbac.require(principal, P_CASES_READ)
        return self.repo.list_cases(status=status, limit=limit)

    def set_case_status(self, case_id: str, status: CaseStatus, principal: Principal, note: str = "") -> CaseRow:
        self.rbac.require(principal, P_CASES_WRITE)
        before = self.repo.get_case(case_id).status
        row = self.repo.update_case(case_id, status=status.value)
        self.audit.record(
            actor=principal.id,
            action="case.status_changed",
            target=case_id,
            case_id=case_id,
            detail={"from": before, "to": status.value, "note": note},
        )
        return row

    def evidence_pack(self, case_id: str, principal: Principal) -> dict[str, Any]:
        self.rbac.require(principal, P_CASES_READ)
        case = self.repo.get_case(case_id)
        runs = self.repo.list_runs(case_id=case_id)
        return {
            "case": _row(case),
            "alerts": [_row(a) for a in self.repo.list_alerts(case_id)],
            "runs": [{**_row(r), "steps": [_row(s) for s in self.repo.list_steps(r.id)]} for r in runs],
            "approvals": [_row(a) for a in self.repo.list_approvals(case_id=case_id)],
            "audit": [_row(a) for a in self.repo.list_audit(case_id=case_id, limit=5000)],
            "audit_chain": self.audit.verify(),
        }

    # ------------------------------------------------------------------ #
    # runs
    # ------------------------------------------------------------------ #
    def start_run(
        self,
        *,
        target: str,
        principal: Principal,
        case_id: str | None = None,
        input: dict[str, Any] | None = None,
        model_profile: str | None = None,
    ) -> RunRow:
        self.rbac.require(principal, P_AGENTS_RUN)
        self.ratelimiter.check(principal.id)
        if target in self.agents:
            kind = "agent"
        elif target in self.workflows:
            kind = "workflow"
        else:
            raise NotFound(f"no agent or workflow named '{target}'")
        if case_id:
            self.repo.get_case(case_id)  # existence check

        run_input = dict(input or {})
        if case_id and "alert" not in run_input:
            alerts = self.repo.list_alerts(case_id)
            if alerts:
                run_input["alert"] = alerts[-1].payload
            case = self.repo.get_case(case_id)
            run_input.setdefault(
                "case", {"id": case.id, "title": case.title, "severity": case.severity, "status": case.status}
            )

        trace_id = new_id("trace")
        run = self.repo.create_run(
            case_id=case_id,
            target_kind=kind,
            target_name=target,
            principal_id=principal.id,
            trace_id=trace_id,
            input=run_input,
        )
        self.repo.update_run(run.id, state={"principal": principal.model_dump(), "model_profile": model_profile})
        self.audit.record(
            actor=principal.id,
            action="run.started",
            target=run.id,
            case_id=case_id,
            run_id=run.id,
            trace_id=trace_id,
            detail={"kind": kind, "target": target},
        )
        metrics.inc("ash_runs_started_total", kind=kind, target=target)
        return self._execute(run.id)

    def resume_run(self, run_id: str, principal: Principal) -> RunRow:
        self.rbac.require(principal, P_AGENTS_RUN)
        run = self.repo.get_run(run_id)
        if run.status != RunStatus.AWAITING_APPROVAL.value:
            raise HarnessError(f"run {run_id} is {run.status}, not awaiting approval")
        if not run.pending_approval_id:
            raise HarnessError(f"run {run_id} has no pending approval recorded")
        approval = self.repo.get_approval(run.pending_approval_id)
        if approval.status == ApprovalStatus.PENDING.value:
            raise HarnessError(f"approval {approval.id} is still pending")
        result = self._approval_to_tool_result(approval)
        state = dict(run.state)
        state["pending_tool_result"] = {
            "call_id": approval.call_id,
            "tool": approval.tool,
            "arguments": approval.arguments,
            "result": result.model_dump(mode="json"),
        }
        self.repo.update_run(run_id, state=state, pending_approval_id=None)
        self.audit.record(
            actor=principal.id,
            action="run.resumed",
            target=run_id,
            case_id=run.case_id,
            run_id=run_id,
            trace_id=run.trace_id,
            detail={"approval_id": approval.id, "status": approval.status},
        )
        return self._execute(run_id)

    def get_run(self, run_id: str, principal: Principal) -> dict[str, Any]:
        self.rbac.require(principal, P_CASES_READ)
        run = self.repo.get_run(run_id)
        return {**_row(run), "steps": [_row(s) for s in self.repo.list_steps(run_id)]}

    def _lock_for(self, run_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._run_locks.setdefault(run_id, threading.Lock())

    def _execute(self, run_id: str) -> RunRow:
        lock = self._lock_for(run_id)
        if not lock.acquire(blocking=False):
            raise HarnessError(f"run {run_id} is already executing")
        try:
            run = self.repo.get_run(run_id)
            principal = Principal(**run.state.get("principal", {"id": run.principal_id, "name": run.principal_id}))
            state = dict(run.state)
            pending = state.pop("pending_tool_result", None)
            ctx = RunContext(
                runtime=self,
                run_id=run.id,
                case_id=run.case_id,
                trace_id=run.trace_id,
                principal=principal,
                agent=run.target_name if run.target_kind == "agent" else None,
                state=state,
                model_profile=state.get("model_profile"),
                max_steps=self.settings.max_agent_steps,
            )
            ctx.pending_tool_result = pending
            self.repo.update_run(run_id, status=RunStatus.RUNNING.value, pending_approval_id=None)
            started = time.perf_counter()
            with log_context(run_id=run.id, case_id=run.case_id, trace_id=run.trace_id, principal=principal.id):
                try:
                    if run.target_kind == "agent":
                        result = self.agents.get(run.target_name).run(ctx, run.input)
                    else:
                        result = self.workflows.get(run.target_name).run(ctx, run.input, self.agents)
                    return self._finish(run, ctx, result, started)
                except ApprovalRequired as ar:
                    self.save_state(ctx)
                    row = self.repo.update_run(
                        run_id, status=RunStatus.AWAITING_APPROVAL.value, pending_approval_id=ar.approval_id
                    )
                    if run.case_id:
                        self.repo.update_case(run.case_id, status=CaseStatus.AWAITING_APPROVAL.value)
                    metrics.inc("ash_runs_paused_total")
                    log.info("run awaiting approval", approval_id=ar.approval_id, tool=ar.tool)
                    return row
                except (GuardrailBlocked, HarnessError, Exception) as exc:  # noqa: BLE001
                    self.save_state(ctx)
                    self.audit.record(
                        actor="harness",
                        action="run.failed",
                        target=run_id,
                        case_id=run.case_id,
                        run_id=run_id,
                        trace_id=run.trace_id,
                        detail={"error": str(exc)[:1000]},
                    )
                    metrics.inc("ash_runs_failed_total", target=run.target_name)
                    log.error("run failed", exc_info=True, error=str(exc))
                    return self.repo.update_run(run_id, status=RunStatus.FAILED.value, error=str(exc)[:4000])
        finally:
            lock.release()

    def _finish(self, run: RunRow, ctx: RunContext, result: AgentResult, started: float) -> RunRow:
        self.save_state(ctx)
        duration = (time.perf_counter() - started) * 1000
        output = result.model_dump(mode="json")
        row = self.repo.update_run(run.id, status=RunStatus.SUCCEEDED.value, output=output)
        if run.case_id:
            fields: dict[str, Any] = {}
            if result.next_status:
                fields["status"] = result.next_status.value
            if result.severity:
                fields["severity"] = result.severity.value
            if result.summary:
                fields["summary"] = result.summary
            if fields:
                self.repo.update_case(run.case_id, **fields)
        self.audit.record(
            actor="harness",
            action="run.succeeded",
            target=run.id,
            case_id=run.case_id,
            run_id=run.id,
            trace_id=run.trace_id,
            detail={
                "summary": result.summary[:500],
                "next_status": result.next_status.value if result.next_status else None,
                "duration_ms": round(duration, 1),
            },
        )
        metrics.inc("ash_runs_succeeded_total", target=run.target_name)
        metrics.observe("ash_run_duration_ms", duration, target=run.target_name)
        return row

    # ------------------------------------------------------------------ #
    # Runtime protocol (called by RunContext)
    # ------------------------------------------------------------------ #
    def chat(
        self, ctx: RunContext, messages: list[Message], tools: list[ToolSpec] | None, profile: str | None
    ) -> ModelResponse:
        meta = {"agent": ctx.agent, "run_id": ctx.run_id, "case_id": ctx.case_id, "trace_id": ctx.trace_id}
        messages = self.guardrails.before_model(messages, meta)
        provider = self.router.get(profile)
        started = time.perf_counter()
        response = provider.chat(messages, tools, metadata=meta)
        response = self.guardrails.after_model(response, meta)
        duration = (time.perf_counter() - started) * 1000
        self.repo.add_step(
            run_id=ctx.run_id,
            type=StepType.MODEL,
            name=f"{provider.name}:{provider.model}",
            payload={"messages": len(messages), "tools": [t.name for t in tools or []]},
            result={
                "content": (response.content or "")[:4000],
                "tool_calls": [tc.model_dump() for tc in response.tool_calls],
                "usage": response.usage.model_dump(),
                "reasoning_chars": len(response.reasoning or ""),
            },
            ok=True,
            duration_ms=duration,
            agent=ctx.agent,
        )
        self.audit.record(
            actor=f"agent:{ctx.agent}",
            action="model.called",
            target=f"{provider.name}:{provider.model}",
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            trace_id=ctx.trace_id,
            detail={"tokens": response.usage.total_tokens, "tool_calls": [tc.name for tc in response.tool_calls]},
        )
        return response

    def tool_specs(self, names: list[str] | None) -> list[ToolSpec]:
        return self.tools.specs(names)

    def note(self, ctx: RunContext, text: str, data: dict[str, Any] | None = None) -> None:
        self.repo.add_step(
            run_id=ctx.run_id,
            type=StepType.NOTE,
            name=text[:200],
            payload=data or {},
            result=None,
            ok=True,
            duration_ms=0.0,
            agent=ctx.agent,
        )

    def save_state(self, ctx: RunContext) -> None:
        self.repo.update_run(ctx.root.run_id, state=ctx.root.state)

    def call_tool(self, ctx: RunContext, call: ToolCall) -> ToolResult:
        meta = {"agent": ctx.agent, "run_id": ctx.run_id, "case_id": ctx.case_id, "trace_id": ctx.trace_id}
        principal = ctx.principal
        agent = self.agents.get(ctx.agent) if ctx.agent and ctx.agent in self.agents else None

        # 1. registry + agent allow-list
        if call.name not in self.tools:
            return self._tool_denied(ctx, call, "unknown tool")
        if agent is not None and call.name not in agent.allowed_tools:
            return self._tool_denied(ctx, call, f"tool not in allow-list of agent '{agent.name}'")
        tool = self.tools.get(call.name)

        # 2. schema validation
        try:
            args = tool.validate(call.arguments)
        except ToolValidationError as exc:
            return self._tool_denied(ctx, call, str(exc))

        # 2b. resume: serve the human decision for the call that was parked.
        #     Matched by call id (resumable agents) or by tool+arguments
        #     (agents that re-run from scratch, e.g. wrapped legacy code).
        pending = ctx.root.pending_tool_result
        if pending and (
            pending.get("call_id") == call.id or (pending.get("tool") == tool.name and pending.get("arguments") == args)
        ):
            ctx.root.pending_tool_result = None
            served = ToolResult(**pending["result"])
            served.call_id = call.id
            self.repo.add_step(
                run_id=ctx.run_id,
                type=StepType.NOTE,
                name=f"served human decision for {tool.name}",
                payload={"approval_id": served.approval_id, "ok": served.ok},
                result=None,
                ok=True,
                duration_ms=0.0,
                agent=ctx.agent,
            )
            return served

        # 3. protective plane
        try:
            args = self.guardrails.before_tool(tool.name, args, meta)
        except GuardrailBlocked as exc:
            return self._tool_denied(ctx, call, str(exc))

        # 4. RBAC + policy
        decision = self.policy.evaluate(tool, principal, ctx.agent)
        self.audit.record(
            actor=f"agent:{ctx.agent}",
            action="policy.evaluated",
            target=tool.name,
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            trace_id=ctx.trace_id,
            detail={
                "decision": decision.decision.value,
                "rule": decision.rule,
                "tier": tool.risk_tier.value,
                "principal": principal.id,
            },
        )
        metrics.inc("ash_policy_decisions_total", decision=decision.decision.value, tier=tool.risk_tier.value)

        if decision.decision == PolicyDecision.DENY:
            return self._tool_denied(ctx, call, decision.reason)

        if decision.decision == PolicyDecision.REQUIRE_APPROVAL:
            approval = self.repo.create_approval(
                run_id=ctx.run_id,
                case_id=ctx.case_id,
                agent=ctx.agent,
                tool=tool.name,
                call_id=call.id,
                arguments=args,
                risk_tier=tool.risk_tier.value,
                reason=decision.reason,
                requested_by=principal.id,
                ttl_seconds=self.settings.approval_ttl_seconds,
            )
            self.repo.add_step(
                run_id=ctx.run_id,
                type=StepType.APPROVAL,
                name=tool.name,
                payload={"arguments": args, "approval_id": approval.id, "tier": tool.risk_tier.value},
                result=None,
                ok=True,
                duration_ms=0.0,
                agent=ctx.agent,
            )
            self.audit.record(
                actor=f"agent:{ctx.agent}",
                action="approval.requested",
                target=approval.id,
                case_id=ctx.case_id,
                run_id=ctx.run_id,
                trace_id=ctx.trace_id,
                detail={"tool": tool.name, "arguments": args, "tier": tool.risk_tier.value},
            )
            metrics.inc("ash_approvals_requested_total", tool=tool.name)
            raise ApprovalRequired(approval.id, tool.name, call.id)

        return self._execute_tool(ctx, call, tool, args, approval_id=None)

    # ------------------------------------------------------------------ #
    def _execute_tool(
        self, ctx: RunContext, call: ToolCall, tool: Any, args: dict[str, Any], approval_id: str | None
    ) -> ToolResult:
        tctx = ToolContext(
            connectors=self.connectors, principal=ctx.principal, case_id=ctx.case_id, run_id=ctx.run_id, agent=ctx.agent
        )
        started = time.perf_counter()
        try:
            value = tool.fn(tctx, **args) if tool.accepts_context else tool.fn(**args)
            duration = (time.perf_counter() - started) * 1000
            result = ToolResult(
                tool=tool.name, call_id=call.id, ok=True, result=value, duration_ms=duration, approval_id=approval_id
            )
        except Exception as exc:  # noqa: BLE001 — tool failures are data for the agent, not crashes
            duration = (time.perf_counter() - started) * 1000
            result = ToolResult(
                tool=tool.name,
                call_id=call.id,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
                duration_ms=duration,
                approval_id=approval_id,
            )
        self.repo.add_step(
            run_id=ctx.run_id,
            type=StepType.TOOL,
            name=tool.name,
            payload={"arguments": args, "approval_id": approval_id},
            result={"ok": result.ok, "result": result.result, "error": result.error},
            ok=result.ok,
            duration_ms=duration,
            agent=ctx.agent,
        )
        self.audit.record(
            actor=f"agent:{ctx.agent}",
            action="tool.executed",
            target=tool.name,
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            trace_id=ctx.trace_id,
            detail={
                "arguments": args,
                "ok": result.ok,
                "tier": tool.risk_tier.value,
                "approval_id": approval_id,
                "error": result.error,
            },
        )
        metrics.inc("ash_tool_calls_total", tool=tool.name, tier=tool.risk_tier.value, ok=str(result.ok).lower())
        metrics.observe("ash_tool_duration_ms", duration, tool=tool.name)
        return result

    def _tool_denied(self, ctx: RunContext, call: ToolCall, reason: str) -> ToolResult:
        self.repo.add_step(
            run_id=ctx.run_id,
            type=StepType.TOOL,
            name=call.name,
            payload={"arguments": call.arguments},
            result={"ok": False, "error": reason},
            ok=False,
            duration_ms=0.0,
            agent=ctx.agent,
        )
        self.audit.record(
            actor=f"agent:{ctx.agent}",
            action="tool.denied",
            target=call.name,
            case_id=ctx.case_id,
            run_id=ctx.run_id,
            trace_id=ctx.trace_id,
            detail={"reason": reason, "arguments": call.arguments},
        )
        metrics.inc("ash_tool_calls_total", tool=call.name, tier="n/a", ok="false")
        return ToolResult(tool=call.name, call_id=call.id, ok=False, error=f"denied: {reason}")

    # ------------------------------------------------------------------ #
    # approvals (HITL)
    # ------------------------------------------------------------------ #
    def list_approvals(
        self, principal: Principal, status: str | None = "pending", case_id: str | None = None
    ) -> list[ApprovalRow]:
        self.rbac.require(principal, P_APPROVALS_READ)
        return self.repo.list_approvals(status=status, case_id=case_id)

    def decide_approval(
        self,
        approval_id: str,
        *,
        approve: bool,
        principal: Principal,
        note: str | None = None,
        auto_resume: bool = True,
    ) -> tuple[ApprovalRow, RunRow | None]:
        self.rbac.require(principal, P_APPROVALS_DECIDE)
        approval = self.repo.get_approval(approval_id)
        if approval.status != ApprovalStatus.PENDING.value:
            raise HarnessError(f"approval {approval_id} is already {approval.status}")
        if approval.requested_by == principal.id:
            raise AuthorizationError("separation of duties: requester cannot approve their own request")
        tool = self.tools.get(approval.tool)
        if approve and not self.rbac.can_execute_tier(principal, tool.risk_tier):
            raise AuthorizationError(f"approver lacks tools:execute:{tool.risk_tier.value} for '{tool.name}'")

        status = ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED
        approval = self.repo.decide_approval(approval_id, status=status, decided_by=principal.id, note=note)
        self.audit.record(
            actor=principal.id,
            action=f"approval.{status.value}",
            target=approval_id,
            case_id=approval.case_id,
            run_id=approval.run_id,
            detail={"tool": approval.tool, "arguments": approval.arguments, "note": note},
        )
        metrics.inc("ash_approvals_decided_total", status=status.value, tool=approval.tool)

        if approve:
            run = self.repo.get_run(approval.run_id)
            exec_ctx = RunContext(
                runtime=self,
                run_id=run.id,
                case_id=run.case_id,
                trace_id=run.trace_id,
                principal=principal,
                agent=approval.agent,
                state={},
                max_steps=self.settings.max_agent_steps,
            )
            result = self._execute_tool(
                exec_ctx,
                ToolCall(id=approval.call_id, name=approval.tool, arguments=approval.arguments),
                tool,
                approval.arguments,
                approval_id=approval.id,
            )
            self.repo.set_approval_result(approval.id, result.model_dump(mode="json"))
            approval = self.repo.get_approval(approval.id)

        run_row: RunRow | None = None
        if auto_resume:
            run_row = self.resume_run(approval.run_id, principal)
        return approval, run_row

    def _approval_to_tool_result(self, approval: ApprovalRow) -> ToolResult:
        if approval.status == ApprovalStatus.APPROVED.value and approval.result:
            return ToolResult(**approval.result)
        reason = {"rejected": "rejected by human approver", "expired": "approval request expired"}.get(
            approval.status, f"approval {approval.status}"
        )
        note = f" ({approval.decision_note})" if approval.decision_note else ""
        return ToolResult(
            tool=approval.tool, call_id=approval.call_id, ok=False, error=f"{reason}{note}", approval_id=approval.id
        )

    # ------------------------------------------------------------------ #
    # audit & health
    # ------------------------------------------------------------------ #
    def list_audit(self, principal: Principal, **filters: Any) -> list[dict[str, Any]]:
        self.rbac.require(principal, P_AUDIT_READ)
        return [_row(a) for a in self.repo.list_audit(**filters)]

    def verify_audit(self, principal: Principal) -> dict[str, Any]:
        self.rbac.require(principal, P_AUDIT_VERIFY)
        return self.audit.verify()

    def readiness(self) -> dict[str, Any]:
        db_ok = self.db.ping()
        models = self.router.health()
        return {"ok": db_ok and all(models.values()), "database": db_ok, "models": models}


def _row(obj: Any) -> dict[str, Any]:
    """ORM row → plain dict (JSON-safe)."""
    out: dict[str, Any] = {}
    for col in obj.__table__.columns:  # type: ignore[attr-defined]
        v = getattr(obj, col.name)
        out[col.name] = v.isoformat() if hasattr(v, "isoformat") else v
    return out

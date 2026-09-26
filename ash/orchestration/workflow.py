"""Workflow orchestration: ordered stages of registered agents with input
mapping and conditional routing. Resumable across human approvals — the
stage index and each stage's agent state are persisted in the run state."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ash.agents.base import RunContext
from ash.agents.registry import AgentRegistry
from ash.core.errors import NotFound
from ash.core.types import AgentResult, Severity

InputMapper = Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
Condition = Callable[[dict[str, Any]], bool]


def default_input(input: dict[str, Any], outputs: dict[str, Any]) -> dict[str, Any]:
    return {**input, "prior_stages": outputs}


@dataclass
class Stage:
    name: str
    agent: str
    input: InputMapper = default_input
    when: Condition | None = None  # receives outputs so far; False → stage skipped
    model_profile: str | None = None


@dataclass
class Workflow:
    name: str
    description: str
    stages: list[Stage]
    tags: list[str] = field(default_factory=list)

    def run(self, ctx: RunContext, input: dict[str, Any], agents: AgentRegistry) -> AgentResult:
        st = ctx.state
        outputs: dict[str, Any] = st.setdefault("outputs", {})
        summaries: list[str] = st.setdefault("summaries", [])
        idx = int(st.get("stage_index", 0))
        last: AgentResult | None = None

        while idx < len(self.stages):
            stage = self.stages[idx]
            st["stage_index"] = idx
            ctx.save()

            if stage.when is not None and not stage.when(outputs):
                outputs[stage.name] = {"skipped": True}
                ctx.note(f"stage '{stage.name}' skipped by condition")
                idx += 1
                continue

            agent = agents.get(stage.agent)
            child = ctx.child(agent=agent.name, state_key=f"stage:{stage.name}", model_profile=stage.model_profile)
            ctx.note(f"stage '{stage.name}' → agent '{agent.name}'", {"stage_index": idx})
            result = agent.run(child, stage.input(input, outputs))  # ApprovalRequired propagates
            outputs[stage.name] = {
                **result.output,
                "_summary": result.summary,
                "_severity": result.severity.value if result.severity else None,
                "_next_status": result.next_status.value if result.next_status else None,
            }
            if result.summary:
                summaries.append(f"[{stage.name}] {result.summary}")
            st["last_result"] = result.model_dump(mode="json")
            last = result
            idx += 1
            st["stage_index"] = idx
            ctx.save()

        final = last or AgentResult(summary="workflow produced no stages")
        return AgentResult(
            output={"stages": outputs, "final": final.output},
            summary=" ".join(summaries) if summaries else final.summary,
            confidence=final.confidence,
            severity=_max_severity(outputs) or final.severity,
            next_status=final.next_status,
        )


def _max_severity(outputs: dict[str, Any]) -> Severity | None:
    best: Severity | None = None
    for o in outputs.values():
        s = o.get("_severity") if isinstance(o, dict) else None
        if s:
            try:
                sev = Severity(s)
            except ValueError:
                continue
            if best is None or sev.rank > best.rank:
                best = sev
    return best


class WorkflowRegistry:
    def __init__(self) -> None:
        self._workflows: dict[str, Workflow] = {}

    def register(self, wf: Workflow, *, replace: bool = False) -> Workflow:
        if wf.name in self._workflows and not replace:
            raise ValueError(f"workflow '{wf.name}' already registered")
        self._workflows[wf.name] = wf
        return wf

    def get(self, name: str) -> Workflow:
        try:
            return self._workflows[name]
        except KeyError:
            raise NotFound(f"unknown workflow '{name}'") from None

    def __contains__(self, name: str) -> bool:
        return name in self._workflows

    def names(self) -> list[str]:
        return sorted(self._workflows)

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "name": w.name,
                "description": w.description,
                "tags": w.tags,
                "stages": [{"name": s.name, "agent": s.agent, "conditional": s.when is not None} for s in w.stages],
            }
            for w in self._workflows.values()
        ]


# --------------------------------------------------------------------------- #
# Reference workflow
# --------------------------------------------------------------------------- #


def _is_true_positive(outputs: dict[str, Any]) -> bool:
    t = outputs.get("triage", {})
    return t.get("verdict") in {"true_positive", "needs_investigation"}


def _needs_response(outputs: dict[str, Any]) -> bool:
    inv = outputs.get("investigate", {})
    sev = inv.get("_severity") or inv.get("severity")
    try:
        return _is_true_positive(outputs) and Severity(str(sev)).rank >= Severity.HIGH.rank
    except ValueError:
        return False


def triage_investigate_respond() -> Workflow:
    return Workflow(
        name="triage_investigate_respond",
        description="Standard SOC pipeline: triage → investigate (if not benign) → respond (if HIGH+).",
        tags=["soc", "reference"],
        stages=[
            Stage(name="triage", agent="triage"),
            Stage(name="investigate", agent="investigate", when=_is_true_positive),
            Stage(name="respond", agent="respond", when=_needs_response),
        ],
    )

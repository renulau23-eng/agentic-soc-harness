"""End-to-end demo: an alert goes through triage → investigate → respond,
pauses on human approval for host isolation, a SOC lead approves, the run
resumes, and the audit chain is verified. Runs fully offline.

    python -m scripts.demo
"""

from __future__ import annotations

import json
import os
import tempfile

from ash.config import Settings
from ash.core.types import AlertIn, Principal, Severity
from ash.runtime import Harness


def run_demo(verbose: bool = True) -> int:
    db_path = os.path.join(tempfile.mkdtemp(prefix="ash-demo-"), "demo.db")
    settings = Settings(database_url=f"sqlite:///{db_path}", log_json=False, log_level="WARNING")
    hz = Harness.build(settings)

    analyst = Principal(id="user:asha", name="asha", roles=["analyst"])
    lead = Principal(id="user:rahul", name="rahul", roles=["soc_lead"])
    auditor = Principal(id="user:meera", name="meera", roles=["auditor"])

    say = print if verbose else (lambda *a, **k: None)

    say("\n=== 1. Alert ingested by SIEM service account ===")
    alert = AlertIn(
        source="siem",
        title="Beaconing to known C2 from FIN-WS-042",
        severity=Severity.HIGH,
        description="Periodic TLS connections to 185.220.101.45 from finance workstation",
        indicators=["185.220.101.45", "evil-updates.xyz"],
        asset_id="host-fin-042",
    )
    case, _ = hz.ingest_alert(alert, analyst)
    say(f"case {case.id}  status={case.status}")

    say("\n=== 2. Analyst runs workflow triage_investigate_respond ===")
    run = hz.start_run(target="triage_investigate_respond", principal=analyst, case_id=case.id)
    say(f"run {run.id}  status={run.status}  pending_approval={run.pending_approval_id}")
    for s in hz.repo.list_steps(run.id):
        say(f"  step {s.seq:>2} {s.type:<8} {s.agent or '-':<12} {s.name}")

    pending = hz.list_approvals(lead)
    assert pending and run.status == "awaiting_approval", "expected a pending approval on isolate_host"
    apr = pending[0]
    say(f"\n=== 3. HITL: approval {apr.id} for {apr.tool}{json.dumps(apr.arguments)} (tier={apr.risk_tier}) ===")

    say("   analyst tries to approve her own request → must be refused")
    try:
        hz.decide_approval(apr.id, approve=True, principal=analyst)
        raise SystemExit("separation of duties failed")
    except Exception as exc:  # noqa: BLE001
        say(f"   refused: {exc}")

    say("   SOC lead approves → tool executes, run resumes automatically")
    approval, run2 = hz.decide_approval(apr.id, approve=True, principal=lead, note="Confirmed C2, isolate.")
    say(f"   approval={approval.status} decided_by={approval.decided_by}")
    assert run2 is not None

    # The respond agent also blocks the indicator (HIGH) — second approval.
    while run2.status == "awaiting_approval":
        nxt = hz.list_approvals(lead)[0]
        say(f"   second approval {nxt.id} for {nxt.tool} → approved by lead")
        _, run2 = hz.decide_approval(nxt.id, approve=True, principal=lead)

    say(f"\n=== 4. Run finished: status={run2.status} ===")
    out = run2.output or {}
    say(f"summary: {out.get('summary')}")
    case = hz.repo.get_case(case.id)
    say(f"case status={case.status} severity={case.severity}")
    for s in hz.repo.list_steps(run2.id):
        say(f"  step {s.seq:>2} {s.type:<8} {s.agent or '-':<12} {s.name}  ok={s.ok}")

    say("\n=== 5. Auditor verifies the hash-chained audit log ===")
    v = hz.verify_audit(auditor)
    say(json.dumps(v))
    assert v["ok"]

    say("\n=== 6. Evidence pack ===")
    ev = hz.evidence_pack(case.id, auditor)
    say(
        f"alerts={len(ev['alerts'])} runs={len(ev['runs'])} approvals={len(ev['approvals'])} "
        f"audit_entries={len(ev['audit'])} chain_ok={ev['audit_chain']['ok']}"
    )
    say(f"\nEDR isolated hosts: {list(hz.connectors.edr.isolated)}")
    say(f"Firewall blocks:    {[b['indicator'] for b in hz.connectors.network.blocked]}")
    say(f"Tickets raised:     {[t['title'] for t in hz.connectors.ticketing.tickets]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_demo())

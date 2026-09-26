"""Same end-to-end demo, but against whatever ASH_DATABASE_URL points at
(used by CI to prove the PostgreSQL path). Tables are created if missing."""

from __future__ import annotations

import os

from ash.config import Settings
from ash.core.types import AlertIn, Principal, Severity
from ash.runtime import Harness


def main() -> int:
    url = os.environ.get("ASH_DATABASE_URL")
    if not url:
        raise SystemExit("set ASH_DATABASE_URL")
    hz = Harness.build(Settings(database_url=url, log_json=False, log_level="WARNING"))
    analyst = Principal(id="user:analyst", name="analyst", roles=["analyst"])
    lead = Principal(id="user:lead", name="lead", roles=["soc_lead"])
    case, _ = hz.ingest_alert(
        AlertIn(
            source="siem",
            title="PG demo: C2 beacon",
            severity=Severity.HIGH,
            indicators=["185.220.101.45"],
            asset_id="host-fin-042",
        ),
        analyst,
    )
    run = hz.start_run(target="triage_investigate_respond", principal=analyst, case_id=case.id)
    while run.status == "awaiting_approval":
        a = hz.list_approvals(lead)[0]
        _, run = hz.decide_approval(a.id, approve=True, principal=lead)
    assert run.status == "succeeded", run.error
    v = hz.audit.verify()
    assert v["ok"], v
    print(f"OK on {url.split('://')[0]}: run={run.id} case_status={hz.repo.get_case(case.id).status} audit={v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

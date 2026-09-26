"""Tamper-evident audit log.

Each entry's hash = SHA-256(prev_hash || canonical JSON of the entry). Any
edit, deletion or reordering breaks the chain; ``verify`` walks the whole
log and reports the first broken link.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from ash.observability import get_logger, metrics
from ash.persistence.models import AuditRow
from ash.persistence.repository import Repository

log = get_logger(__name__)

GENESIS = "0" * 64


def _canonical_ts(ts: datetime) -> str:
    """Databases differ in tz handling; hash a normalised naive-UTC form."""
    if ts.tzinfo is not None:
        ts = ts.astimezone(UTC).replace(tzinfo=None)
    return ts.isoformat()


def compute_hash(prev_hash: str, ts: datetime, actor: str, action: str, target: str, detail: dict[str, Any]) -> str:
    body = json.dumps(
        {"ts": _canonical_ts(ts), "actor": actor, "action": action, "target": target, "detail": detail},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, repo: Repository):
        self._repo = repo

    def record(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        detail: dict[str, Any] | None = None,
        case_id: str | None = None,
        run_id: str | None = None,
        trace_id: str | None = None,
    ) -> AuditRow:
        row = self._repo.append_audit(
            actor=actor,
            action=action,
            target=target,
            detail=detail or {},
            case_id=case_id,
            run_id=run_id,
            trace_id=trace_id,
            hasher=compute_hash,
        )
        metrics.inc("ash_audit_entries_total", action=action)
        log.info("audit", action=action, actor=actor, target=target, audit_seq=row.seq)
        return row

    def verify(self) -> dict[str, Any]:
        prev = GENESIS
        count = 0
        for row in self._repo.iter_audit():
            ts = row.ts
            expected = compute_hash(prev, ts, row.actor, row.action, row.target, row.detail)
            if row.prev_hash != prev or row.hash != expected:
                return {
                    "ok": False,
                    "entries": count,
                    "broken_at_seq": row.seq,
                    "reason": "prev_hash mismatch" if row.prev_hash != prev else "hash mismatch",
                }
            prev = row.hash
            count += 1
        return {"ok": True, "entries": count, "head": prev}

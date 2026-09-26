"""Database engine/session management and the repository layer.

The repository is intentionally thin and explicit: every write is a method
with a clear name, so the runtime reads like a protocol rather than an ORM
tutorial. Sessions are short-lived and commit per operation.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ash.core.errors import NotFound
from ash.core.types import ApprovalStatus, CaseStatus, RunStatus, StepType, new_id
from ash.persistence.models import AlertRow, ApprovalRow, AuditRow, Base, CaseRow, RunRow, StepRow


def make_engine(url: str) -> Engine:
    kwargs: dict[str, Any] = {"future": True, "pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):  # type: ignore[no-untyped-def]
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

    return engine


class Database:
    def __init__(self, url: str):
        self.url = url
        self.engine = make_engine(url)
        self._session_factory = sessionmaker(bind=self.engine, expire_on_commit=False, future=True)

    def create_all(self) -> None:
        Base.metadata.create_all(self.engine)

    def drop_all(self) -> None:
        Base.metadata.drop_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = self._session_factory()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    def ping(self) -> bool:
        try:
            with self.engine.connect() as conn:
                conn.exec_driver_sql("SELECT 1")
            return True
        except Exception:
            return False


def _now() -> datetime:
    return datetime.now(UTC)


def _dt(value: datetime | None) -> datetime | None:
    """SQLite drops tzinfo; normalise to aware UTC for comparisons."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


class Repository:
    def __init__(self, db: Database):
        self.db = db

    # ----------------------------------------------------------- cases
    def create_case(
        self, *, title: str, severity: str, created_by: str, context: dict[str, Any] | None = None, summary: str = ""
    ) -> CaseRow:
        with self.db.session() as s:
            row = CaseRow(
                id=new_id("case"),
                title=title,
                severity=severity,
                status=CaseStatus.NEW.value,
                created_by=created_by,
                context=context or {},
                summary=summary,
            )
            s.add(row)
            s.flush()
            return row

    def get_case(self, case_id: str) -> CaseRow:
        with self.db.session() as s:
            row = s.get(CaseRow, case_id)
            if not row:
                raise NotFound(f"case {case_id} not found")
            return row

    def list_cases(self, *, status: str | None = None, limit: int = 100) -> list[CaseRow]:
        with self.db.session() as s:
            q = select(CaseRow).order_by(CaseRow.created_at.desc()).limit(limit)
            if status:
                q = q.where(CaseRow.status == status)
            return list(s.scalars(q))

    def update_case(self, case_id: str, **fields: Any) -> CaseRow:
        with self.db.session() as s:
            row = s.get(CaseRow, case_id)
            if not row:
                raise NotFound(f"case {case_id} not found")
            for k, v in fields.items():
                setattr(row, k, v)
            s.flush()
            return row

    def add_alert(self, *, case_id: str, source: str, title: str, severity: str, payload: dict[str, Any]) -> AlertRow:
        with self.db.session() as s:
            row = AlertRow(
                id=new_id("alert"), case_id=case_id, source=source, title=title, severity=severity, payload=payload
            )
            s.add(row)
            s.flush()
            return row

    def list_alerts(self, case_id: str) -> list[AlertRow]:
        with self.db.session() as s:
            return list(s.scalars(select(AlertRow).where(AlertRow.case_id == case_id).order_by(AlertRow.received_at)))

    # ------------------------------------------------------------ runs
    def create_run(
        self,
        *,
        case_id: str | None,
        target_kind: str,
        target_name: str,
        principal_id: str,
        trace_id: str,
        input: dict[str, Any],
    ) -> RunRow:
        with self.db.session() as s:
            row = RunRow(
                id=new_id("run"),
                case_id=case_id,
                target_kind=target_kind,
                target_name=target_name,
                status=RunStatus.PENDING.value,
                principal_id=principal_id,
                trace_id=trace_id,
                input=input,
                state={},
            )
            s.add(row)
            s.flush()
            return row

    def get_run(self, run_id: str) -> RunRow:
        with self.db.session() as s:
            row = s.get(RunRow, run_id)
            if not row:
                raise NotFound(f"run {run_id} not found")
            return row

    def list_runs(self, *, case_id: str | None = None, limit: int = 100) -> list[RunRow]:
        with self.db.session() as s:
            q = select(RunRow).order_by(RunRow.created_at.desc()).limit(limit)
            if case_id:
                q = q.where(RunRow.case_id == case_id)
            return list(s.scalars(q))

    def update_run(self, run_id: str, **fields: Any) -> RunRow:
        with self.db.session() as s:
            row = s.get(RunRow, run_id)
            if not row:
                raise NotFound(f"run {run_id} not found")
            for k, v in fields.items():
                setattr(row, k, v)
            s.flush()
            return row

    def add_step(
        self,
        *,
        run_id: str,
        type: StepType,
        name: str,
        payload: dict[str, Any],
        result: dict[str, Any] | None,
        ok: bool,
        duration_ms: float,
        agent: str | None,
    ) -> StepRow:
        with self.db.session() as s:
            seq = s.scalar(select(StepRow.seq).where(StepRow.run_id == run_id).order_by(StepRow.seq.desc()).limit(1))
            row = StepRow(
                id=new_id("step"),
                run_id=run_id,
                seq=(seq or 0) + 1,
                type=type.value,
                name=name,
                payload=payload,
                result=result,
                ok=ok,
                duration_ms=duration_ms,
                agent=agent,
            )
            s.add(row)
            s.flush()
            return row

    def list_steps(self, run_id: str) -> list[StepRow]:
        with self.db.session() as s:
            return list(s.scalars(select(StepRow).where(StepRow.run_id == run_id).order_by(StepRow.seq)))

    # ------------------------------------------------------- approvals
    def create_approval(
        self,
        *,
        run_id: str,
        case_id: str | None,
        agent: str | None,
        tool: str,
        call_id: str,
        arguments: dict[str, Any],
        risk_tier: str,
        reason: str,
        requested_by: str,
        ttl_seconds: int,
    ) -> ApprovalRow:
        with self.db.session() as s:
            row = ApprovalRow(
                id=new_id("apr"),
                run_id=run_id,
                case_id=case_id,
                agent=agent,
                tool=tool,
                call_id=call_id,
                arguments=arguments,
                risk_tier=risk_tier,
                reason=reason,
                status=ApprovalStatus.PENDING.value,
                requested_by=requested_by,
                expires_at=_now() + timedelta(seconds=ttl_seconds),
            )
            s.add(row)
            s.flush()
            return row

    def get_approval(self, approval_id: str) -> ApprovalRow:
        with self.db.session() as s:
            row = s.get(ApprovalRow, approval_id)
            if not row:
                raise NotFound(f"approval {approval_id} not found")
            if row.status == ApprovalStatus.PENDING.value and _dt(row.expires_at) and _dt(row.expires_at) < _now():
                row.status = ApprovalStatus.EXPIRED.value
                s.flush()
            return row

    def list_approvals(
        self, *, status: str | None = None, case_id: str | None = None, limit: int = 100
    ) -> list[ApprovalRow]:
        with self.db.session() as s:
            q = select(ApprovalRow).order_by(ApprovalRow.requested_at.desc()).limit(limit)
            if status:
                q = q.where(ApprovalRow.status == status)
            if case_id:
                q = q.where(ApprovalRow.case_id == case_id)
            return list(s.scalars(q))

    def decide_approval(
        self,
        approval_id: str,
        *,
        status: ApprovalStatus,
        decided_by: str,
        note: str | None,
        result: dict[str, Any] | None = None,
    ) -> ApprovalRow:
        with self.db.session() as s:
            row = s.get(ApprovalRow, approval_id, with_for_update=not self.db.url.startswith("sqlite"))
            if not row:
                raise NotFound(f"approval {approval_id} not found")
            if row.status != ApprovalStatus.PENDING.value:
                raise ValueError(f"approval {approval_id} already {row.status}")
            row.status = status.value
            row.decided_by = decided_by
            row.decided_at = _now()
            row.decision_note = note
            row.result = result
            s.flush()
            return row

    def set_approval_result(self, approval_id: str, result: dict[str, Any]) -> None:
        with self.db.session() as s:
            row = s.get(ApprovalRow, approval_id)
            if row:
                row.result = result

    # ----------------------------------------------------------- audit
    def last_audit_hash(self, s: Session) -> str:
        last = s.scalar(select(AuditRow.hash).order_by(AuditRow.seq.desc()).limit(1))
        return last or "0" * 64

    def append_audit(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        detail: dict[str, Any],
        case_id: str | None,
        run_id: str | None,
        trace_id: str | None,
        hasher: Any,
    ) -> AuditRow:
        with self.db.session() as s:
            prev = self.last_audit_hash(s)
            ts = _now()
            digest = hasher(prev, ts, actor, action, target, detail)
            row = AuditRow(
                ts=ts,
                actor=actor,
                action=action,
                target=target,
                detail=detail,
                case_id=case_id,
                run_id=run_id,
                trace_id=trace_id,
                prev_hash=prev,
                hash=digest,
            )
            s.add(row)
            s.flush()
            return row

    def list_audit(
        self,
        *,
        case_id: str | None = None,
        run_id: str | None = None,
        action: str | None = None,
        limit: int = 500,
        after_seq: int = 0,
    ) -> list[AuditRow]:
        with self.db.session() as s:
            q = select(AuditRow).where(AuditRow.seq > after_seq).order_by(AuditRow.seq).limit(limit)
            if case_id:
                q = q.where(AuditRow.case_id == case_id)
            if run_id:
                q = q.where(AuditRow.run_id == run_id)
            if action:
                q = q.where(AuditRow.action == action)
            return list(s.scalars(q))

    def iter_audit(self, batch: int = 1000) -> Iterator[AuditRow]:
        after = 0
        while True:
            rows = self.list_audit(limit=batch, after_seq=after)
            if not rows:
                return
            yield from rows
            after = rows[-1].seq

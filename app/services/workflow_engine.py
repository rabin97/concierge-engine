"""Workflow engine: the state machine. Postgres is the source of truth; Celery only carries "run step X".

Locking order (avoids deadlocks): always lock the workflows row first, then its steps.
Every side-effect-producing transition is a conditional UPDATE, so replays are no-ops.
"""
import logging
import random
import uuid
from datetime import datetime, timezone
from typing import Callable
from uuid import UUID

from sqlalchemy import Connection

from app.config import settings
from app.db import jdump, q, tx
from app.schemas.task_tree import TaskTree

log = logging.getLogger(__name__)

TERMINAL = {"SUCCEEDED", "FAILED", "SKIPPED", "CANCELLED"}
WF_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}
QUEUE_FOR = {"BOOK_SERVICE": "booking", "SEND_NOTIFICATION": "notify", "SCHEDULE_REMINDER": "notify"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------ helpers
def add_event(conn: Connection, wf_id: UUID, type_: str, data: dict | None = None) -> None:
    q(conn, "INSERT INTO workflow_events (workflow_id, type, data) VALUES (:w, :t, CAST(:d AS jsonb))",
      w=wf_id, t=type_, d=jdump(data or {}))


def enqueue(conn: Connection, task: str, payload: dict) -> None:
    """Transactional outbox: the message is committed with the state change, the relay publishes it."""
    q(conn, "INSERT INTO outbox (topic, payload) VALUES (:t, CAST(:p AS jsonb))", t=task, p=jdump(payload))


def _lock_workflow(conn: Connection, wf_id: UUID):
    return q(conn, "SELECT id, status, user_id FROM workflows WHERE id=:id FOR UPDATE", id=wf_id).mappings().first()


def _enqueue_step(conn: Connection, step_id: UUID, step_type: str) -> None:
    enqueue(conn, "run_step", {"step_id": str(step_id), "queue": QUEUE_FOR[step_type]})


# ------------------------------------------------------------------ workflow lifecycle
def create_workflow(user_id: UUID, idempotency_key: str, prompt: str,
                    guard: dict | None = None) -> tuple[UUID, str, bool]:
    """``prompt`` must already be screened (PII masked). ``guard`` is recorded on the CREATED event."""
    with tx() as conn:
        row = q(conn, """INSERT INTO workflows (id, user_id, client_request_id, prompt_redacted, status)
                         VALUES (:id, :u, :k, :p, 'PLANNING')
                         ON CONFLICT (user_id, client_request_id) DO NOTHING RETURNING id, status""",
                id=uuid.uuid4(), u=user_id, k=idempotency_key, p=prompt).mappings().first()
        if row is None:  # same Idempotency-Key -> same workflow
            existing = q(conn, "SELECT id, status FROM workflows WHERE user_id=:u AND client_request_id=:k",
                         u=user_id, k=idempotency_key).mappings().one()
            return existing["id"], existing["status"], False
        add_event(conn, row["id"], "CREATED", {"guard": guard} if guard else None)
        enqueue(conn, "plan_workflow", {"workflow_id": str(row["id"]), "queue": "intent"})
        return row["id"], row["status"], True


def set_needs_input(wf_id: UUID, question: str) -> None:
    with tx() as conn:
        q(conn, """UPDATE workflows SET status='NEEDS_INPUT', question=:qq, updated_at=now(), version=version+1
                   WHERE id=:id AND status='PLANNING'""", id=wf_id, qq=question)
        add_event(conn, wf_id, "NEEDS_INPUT", {"question": question})


def answer(wf_id: UUID, user_id: UUID, text: str) -> bool:
    with tx() as conn:
        row = q(conn, """UPDATE workflows SET status='PLANNING', question=NULL,
                           prompt_redacted = prompt_redacted || ' ' || :a, updated_at=now(), version=version+1
                         WHERE id=:id AND user_id=:u AND status='NEEDS_INPUT' RETURNING id""",
                id=wf_id, u=user_id, a=text).first()
        if row:
            add_event(conn, wf_id, "ANSWERED")
            enqueue(conn, "plan_workflow", {"workflow_id": str(wf_id), "queue": "intent"})
        return row is not None


def save_plan(wf_id: UUID, tree: TaskTree, plan_hash: str, prompt_version: str, summary: str | None,
              used_preferences: list[str]) -> str:
    status = "AWAITING_CONFIRMATION" if tree.needs_confirmation() else "RUNNING"
    with tx() as conn:
        wf = _lock_workflow(conn, wf_id)
        if wf is None or wf["status"] != "PLANNING":
            return wf["status"] if wf else "MISSING"
        q(conn, """UPDATE workflows SET plan=CAST(:plan AS jsonb), plan_hash=:h, prompt_version=:pv, summary=:s,
                     status=:st, updated_at=now(), version=version+1 WHERE id=:id""",
          id=wf_id, plan=jdump(tree.model_dump(mode="json")), h=plan_hash, pv=prompt_version, s=summary, st=status)
        add_event(conn, wf_id, "PLANNED", {"plan_hash": plan_hash, "preferences_applied": used_preferences})
        if status == "RUNNING":
            _materialize(conn, wf_id, tree)
            advance(conn, wf_id)
    return status


def confirm(wf_id: UUID, user_id: UUID) -> bool:
    with tx() as conn:
        row = q(conn, """UPDATE workflows SET status='RUNNING', updated_at=now(), version=version+1
                         WHERE id=:id AND user_id=:u AND status='AWAITING_CONFIRMATION' RETURNING plan""",
                id=wf_id, u=user_id).mappings().first()
        if row is None:
            return False  # already confirmed, cancelled, or not yours: idempotent no-op
        add_event(conn, wf_id, "CONFIRMED_BY_USER")
        _materialize(conn, wf_id, TaskTree.model_validate(row["plan"]))
        advance(conn, wf_id)
        return True


def _materialize(conn: Connection, wf_id: UUID, tree: TaskTree) -> None:
    for s in tree.steps:
        q(conn, """INSERT INTO workflow_steps (id, workflow_id, step_key, type, params, depends_on, run_condition, status)
                   VALUES (:id, :w, :k, :t, CAST(:p AS jsonb), :d, :rc, 'PENDING')
                   ON CONFLICT (workflow_id, step_key) DO NOTHING""",
          id=uuid.uuid4(), w=wf_id, k=s.step_key, t=s.type.value,
          p=jdump(s.params.model_dump(mode="json")), d=s.depends_on, rc=s.run_condition)


def advance(conn: Connection, wf_id: UUID, now: datetime | None = None) -> None:
    """Move PENDING steps whose dependencies are settled. Caller must hold the workflow row lock."""
    now = now or utcnow()
    wf = q(conn, "SELECT status FROM workflows WHERE id=:id", id=wf_id).mappings().one()
    if wf["status"] in WF_TERMINAL:
        return
    steps = q(conn, """SELECT id, step_key, type, params, depends_on, run_condition, status
                       FROM workflow_steps WHERE workflow_id=:w ORDER BY step_key FOR UPDATE""",
              w=wf_id).mappings().all()
    if not steps:
        return
    status = {s["step_key"]: s["status"] for s in steps}
    changed = True
    while changed:
        changed = False
        for s in steps:
            if status[s["step_key"]] != "PENDING":
                continue
            deps = [status[d] for d in s["depends_on"]]
            failed_dep = any(d in {"FAILED", "SKIPPED", "CANCELLED"} for d in deps)
            if s["run_condition"] == "ON_SUCCESS" and failed_dep:
                new = "SKIPPED"
                q(conn, "UPDATE workflow_steps SET status='SKIPPED', updated_at=now() WHERE id=:id", id=s["id"])
            elif all(d == "SUCCEEDED" for d in deps) or (s["run_condition"] == "ALWAYS" and all(d in TERMINAL for d in deps)):
                fire_at = s["params"].get("fire_at")
                if s["type"] == "SCHEDULE_REMINDER" and fire_at and datetime.fromisoformat(fire_at) > now:
                    new = "SCHEDULED"
                    q(conn, "UPDATE workflow_steps SET status='SCHEDULED', updated_at=now() WHERE id=:id", id=s["id"])
                    q(conn, """INSERT INTO scheduled_jobs (step_id, due_at) VALUES (:s, :d)
                               ON CONFLICT (step_id) DO UPDATE SET due_at=EXCLUDED.due_at, state='WAITING'""",
                      s=s["id"], d=fire_at)
                else:
                    new = "QUEUED"
                    q(conn, "UPDATE workflow_steps SET status='QUEUED', updated_at=now() WHERE id=:id", id=s["id"])
                    _enqueue_step(conn, s["id"], s["type"])
            else:
                continue
            status[s["step_key"]] = new
            add_event(conn, wf_id, f"STEP_{new}", {"step": s["step_key"]})
            changed = True

    if all(v in TERMINAL for v in status.values()):
        final = "FAILED" if any(v in {"FAILED", "SKIPPED"} for v in status.values()) else "COMPLETED"
        q(conn, "UPDATE workflows SET status=:s, updated_at=now(), version=version+1 WHERE id=:id", s=final, id=wf_id)
        add_event(conn, wf_id, f"WORKFLOW_{final}")


# ------------------------------------------------------------------ step execution
def claim_step(step_id: UUID):
    """Only one worker wins; a duplicate Celery message gets None and exits."""
    with tx() as conn:
        return q(conn, """UPDATE workflow_steps s
                          SET status='RUNNING', attempt=attempt+1, updated_at=now(),
                              lease_until=now() + make_interval(secs => :lease)
                          FROM workflows w
                          WHERE s.id=:id AND s.status='QUEUED' AND w.id=s.workflow_id
                          RETURNING s.id, s.workflow_id, s.step_key, s.type, s.params, s.attempt, w.user_id""",
                 id=step_id, lease=settings.step_lease_seconds).mappings().first()


def mark_waiting_external(step_id: UUID) -> None:
    with tx() as conn:
        q(conn, """UPDATE workflow_steps SET status='WAITING_EXTERNAL', lease_until=NULL, updated_at=now()
                   WHERE id=:id AND status='RUNNING'""", id=step_id)


def finish_step_in_tx(conn: Connection, wf_id: UUID, step_id: UUID, status: str, error: str | None = None) -> bool:
    row = q(conn, """UPDATE workflow_steps SET status=:s, lease_until=NULL, last_error=:e, updated_at=now()
                     WHERE id=:id AND status IN ('RUNNING', 'WAITING_EXTERNAL', 'RETRYING') RETURNING step_key""",
            id=step_id, s=status, e=error).first()
    if row is None:
        return False
    add_event(conn, wf_id, f"STEP_{status}", {"step": row[0], "error": error})
    advance(conn, wf_id)
    return True


def finish_step(wf_id: UUID, step_id: UUID, status: str, error: str | None = None) -> bool:
    with tx() as conn:
        _lock_workflow(conn, wf_id)
        return finish_step_in_tx(conn, wf_id, step_id, status, error)


def schedule_retry(wf_id: UUID, step_id: UUID, attempt: int, error: str) -> None:
    if attempt >= settings.max_step_attempts:
        finish_step(wf_id, step_id, "FAILED", f"max attempts reached: {error}")
        return
    delay = min(300, 2 ** attempt * 2) * random.uniform(0.5, 1.0)  # exponential backoff, jitter
    with tx() as conn:
        row = q(conn, """UPDATE workflow_steps SET status='RETRYING', lease_until=NULL, last_error=:e, updated_at=now()
                         WHERE id=:id AND status='RUNNING' RETURNING id""", id=step_id, e=error).first()
        if row:
            q(conn, """INSERT INTO scheduled_jobs (step_id, due_at) VALUES (:s, now() + make_interval(secs => :d))
                       ON CONFLICT (step_id) DO UPDATE SET due_at=EXCLUDED.due_at, state='WAITING'""",
              s=step_id, d=delay)
            add_event(conn, wf_id, "STEP_RETRYING", {"step_id": str(step_id), "in_seconds": round(delay, 1),
                                                     "error": error})


def cancel(wf_id: UUID, user_id: UUID) -> str:
    with tx() as conn:
        wf = _lock_workflow(conn, wf_id)
        if wf is None or wf["user_id"] != user_id:
            return "NOT_FOUND"
        if wf["status"] in WF_TERMINAL:
            return wf["status"]
        q(conn, "UPDATE workflows SET status='CANCELLED', updated_at=now(), version=version+1 WHERE id=:id", id=wf_id)
        q(conn, """UPDATE workflow_steps SET status='CANCELLED', lease_until=NULL, updated_at=now()
                   WHERE workflow_id=:w AND status NOT IN ('SUCCEEDED','FAILED','SKIPPED','CANCELLED')""", w=wf_id)
        q(conn, """UPDATE scheduled_jobs j SET state='CANCELLED' FROM workflow_steps s
                   WHERE j.step_id=s.id AND s.workflow_id=:w AND j.state='WAITING'""", w=wf_id)
        bookings = q(conn, """SELECT b.id FROM vendor_bookings b JOIN workflow_steps s ON s.id=b.step_id
                              WHERE s.workflow_id=:w AND b.status NOT IN ('COMPLETED','CANCELLED','FAILED')""",
                     w=wf_id).all()
        for (booking_id,) in bookings:
            enqueue(conn, "cancel_vendor_booking", {"booking_id": str(booking_id), "queue": "booking"})
        add_event(conn, wf_id, "WORKFLOW_CANCELLED")
        return "CANCELLED"


# ------------------------------------------------------------------ scheduler / relay / reconciler
def fire_due_jobs(limit: int = 200) -> int:
    with tx() as conn:
        fired = q(conn, """WITH due AS (
                               SELECT id FROM scheduled_jobs WHERE state='WAITING' AND due_at <= now()
                               ORDER BY due_at LIMIT :n FOR UPDATE SKIP LOCKED)
                           UPDATE scheduled_jobs j SET state='FIRED' FROM due WHERE j.id=due.id
                           RETURNING j.step_id""", n=limit).all()
        for (step_id,) in fired:
            row = q(conn, """UPDATE workflow_steps SET status='QUEUED', updated_at=now()
                             WHERE id=:id AND status IN ('SCHEDULED','RETRYING') RETURNING type""", id=step_id).first()
            if row:
                _enqueue_step(conn, step_id, row[0])
        return len(fired)


def relay_outbox(send: Callable[[str, dict], None], limit: int = 100) -> int:
    with tx() as conn:
        rows = q(conn, """SELECT id, topic, payload FROM outbox WHERE sent_at IS NULL
                          ORDER BY id LIMIT :n FOR UPDATE SKIP LOCKED""", n=limit).mappings().all()
        for r in rows:
            send(r["topic"], r["payload"])  # may duplicate if commit fails afterwards: consumers are idempotent
            q(conn, "UPDATE outbox SET sent_at=now() WHERE id=:id", id=r["id"])
        return len(rows)


def reconcile() -> dict:
    """Recovers anything a crash or a lost Redis message left behind."""
    with tx() as conn:
        expired = q(conn, """UPDATE workflow_steps SET status='QUEUED', lease_until=NULL, updated_at=now()
                             WHERE status='RUNNING' AND lease_until < now() RETURNING id, type""").all()
        stale = q(conn, """UPDATE workflow_steps SET updated_at=now()
                           WHERE status='QUEUED' AND updated_at < now() - interval '2 minutes' RETURNING id, type""").all()
        for step_id, step_type in [*expired, *stale]:
            _enqueue_step(conn, step_id, step_type)
        inbox = q(conn, """SELECT id FROM webhook_inbox WHERE state='RECEIVED'
                           AND received_at < now() - interval '30 seconds' LIMIT 100""").all()
        for (inbox_id,) in inbox:
            enqueue(conn, "process_webhook", {"inbox_id": inbox_id, "queue": "webhook"})
    return {"expired_leases": len(expired), "stale_queued": len(stale), "stuck_webhooks": len(inbox)}


# ------------------------------------------------------------------ read model
def get_view(wf_id: UUID, user_id: UUID) -> dict | None:
    with tx() as conn:
        wf = q(conn, "SELECT * FROM workflows WHERE id=:id AND user_id=:u", id=wf_id, u=user_id).mappings().first()
        if wf is None:
            return None
        steps = q(conn, """SELECT step_key, type, status, attempt, last_error FROM workflow_steps
                           WHERE workflow_id=:w ORDER BY step_key""", w=wf_id).mappings().all()
        booking = q(conn, """SELECT b.vendor, b.vendor_ref, b.status FROM vendor_bookings b
                             JOIN workflow_steps s ON s.id=b.step_id WHERE s.workflow_id=:w LIMIT 1""",
                    w=wf_id).mappings().first()
        notes = q(conn, """SELECT s.step_key, n.channel, n.template, n.status FROM notifications n
                           JOIN workflow_steps s ON s.id=n.step_id WHERE s.workflow_id=:w ORDER BY n.created_at""",
                  w=wf_id).mappings().all()
        events = q(conn, "SELECT type, data, at FROM workflow_events WHERE workflow_id=:w ORDER BY id",
                   w=wf_id).mappings().all()
    return {
        "workflow_id": wf["id"], "status": wf["status"], "summary": wf["summary"], "question": wf["question"],
        "plan": wf["plan"], "steps": [dict(s) for s in steps], "booking": dict(booking) if booking else None,
        "notifications": [dict(n) for n in notes],
        "events": [{"type": e["type"], "data": e["data"], "at": e["at"].isoformat()} for e in events],
    }

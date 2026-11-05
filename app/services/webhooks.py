"""Idempotent webhook ingestion: dedupe at the door (inbox), apply forward-only transitions (status rank)."""
import hashlib
import json
import logging
import uuid
from uuid import UUID

from app.db import jdump, q, tx
from app.services import workflow_engine as wfe

log = logging.getLogger(__name__)

STATUS_RANK = {"REQUESTED": 10, "CONFIRMED": 20, "ASSIGNED": 30, "IN_PROGRESS": 40, "COMPLETED": 50,
               "CANCELLED": 90, "FAILED": 90}


def idempotency_key(source: str, payload: dict) -> str:
    event_id = payload.get("event_id")
    if event_id:
        return f"{source}:{event_id}"
    canonical = json.dumps(payload, sort_keys=True).encode()
    return f"{source}:sha256:{hashlib.sha256(canonical).hexdigest()}"


def ingest(source: str, payload: dict) -> tuple[int | None, bool]:
    """Returns (inbox_id, is_new). A duplicate returns (None, False) and changes nothing."""
    with tx() as conn:
        row = q(conn, """INSERT INTO webhook_inbox (idempotency_key, source, event_type, payload)
                         VALUES (:k, :s, :t, CAST(:p AS jsonb))
                         ON CONFLICT (idempotency_key) DO NOTHING RETURNING id""",
                k=idempotency_key(source, payload), s=source, t=payload.get("status", "unknown"),
                p=jdump(payload)).first()
    return (row[0], True) if row else (None, False)


def process_vendor_event(inbox_id: int) -> str:
    with tx() as conn:
        inbox = q(conn, "SELECT id, source, payload, state FROM webhook_inbox WHERE id=:id FOR UPDATE",
                  id=inbox_id).mappings().first()
        if inbox is None or inbox["state"] != "RECEIVED":
            return "SKIPPED"
        p = inbox["payload"]
        new_status = p.get("status")
        rank = STATUS_RANK.get(new_status)
        step_id = p.get("client_reference")
        step = q(conn, "SELECT id, workflow_id FROM workflow_steps WHERE id=:id", id=step_id).mappings().first() \
            if step_id else None
        if rank is None or step is None:
            q(conn, "UPDATE webhook_inbox SET state='FAILED', processed_at=now() WHERE id=:id", id=inbox_id)
            return "FAILED"

        wf_id: UUID = step["workflow_id"]
        wfe._lock_workflow(conn, wf_id)  # lock order: workflow first

        # The webhook can beat our own "booking created" write; create the row if missing.
        q(conn, """INSERT INTO vendor_bookings (id, step_id, vendor, vendor_ref, status, status_rank)
                   VALUES (:id, :s, :v, :ref, 'REQUESTED', 10) ON CONFLICT (step_id) DO NOTHING""",
          id=uuid.uuid4(), s=step_id, v=inbox["source"], ref=p.get("booking_ref"))
        moved = q(conn, """UPDATE vendor_bookings
                           SET status=:st, status_rank=:r, vendor_ref=COALESCE(vendor_ref, :ref),
                               version=version+1, updated_at=now()
                           WHERE step_id=:s AND status_rank < :r RETURNING id""",
                  st=new_status, r=rank, ref=p.get("booking_ref"), s=step_id).first()
        if moved is None:
            q(conn, "UPDATE webhook_inbox SET state='IGNORED_STALE', processed_at=now() WHERE id=:id", id=inbox_id)
            wfe.add_event(conn, wf_id, "VENDOR_EVENT_STALE", {"status": new_status, "event_id": p.get("event_id")})
            return "IGNORED_STALE"

        wfe.add_event(conn, wf_id, f"VENDOR_{new_status}", {"booking_ref": p.get("booking_ref")})
        if new_status in {"CONFIRMED", "ASSIGNED", "IN_PROGRESS", "COMPLETED"}:
            wfe.finish_step_in_tx(conn, wf_id, step_id, "SUCCEEDED")  # no-op if already SUCCEEDED
        elif new_status in {"CANCELLED", "FAILED"}:
            wfe.finish_step_in_tx(conn, wf_id, step_id, "FAILED", f"vendor {new_status.lower()}")
        q(conn, "UPDATE webhook_inbox SET state='PROCESSED', processed_at=now() WHERE id=:id", id=inbox_id)
        return "PROCESSED"

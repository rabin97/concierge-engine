"""What each step type does. A handler either finishes the step, parks it (WAITING_EXTERNAL),
or raises a transient error so the engine schedules a retry."""
import logging
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

from app.agents.planner import SERVICE_LABELS
from app.db import q, tx
from app.services import workflow_engine as wfe
from app.services.notifications import router
from app.services.notifications.providers import ProviderError
from app.services.vendor_client import PermanentVendorError, TransientVendorError, VendorClient

log = logging.getLogger(__name__)


def _user(user_id) -> dict:
    with tx() as conn:
        return dict(q(conn, "SELECT id, name, phone_e164, email, timezone FROM users WHERE id=:id",
                      id=user_id).mappings().one())


def _booking_context(workflow_id, user: dict) -> dict:
    with tx() as conn:
        row = q(conn, """SELECT s.params, b.vendor_ref FROM workflow_steps s
                         LEFT JOIN vendor_bookings b ON b.step_id = s.id
                         WHERE s.workflow_id=:w AND s.type='BOOK_SERVICE' ORDER BY s.step_key LIMIT 1""",
                w=workflow_id).mappings().first()
    if row is None:
        return {"name": user["name"], "service": "service", "when": "", "booking_ref": "-", "extras": ""}
    p = row["params"]
    tz = ZoneInfo(user["timezone"])
    start = datetime.fromisoformat(p["window"]["start"]).astimezone(tz)
    end = datetime.fromisoformat(p["window"]["end"]).astimezone(tz)
    flags = [k.replace("_", " ") for k, v in p.get("constraints", {}).items() if v]
    return {
        "name": user["name"],
        "service": SERVICE_LABELS[p["service_code"]],
        "when": f"{start:%a %d %b}, {start:%H:%M}-{end:%H:%M}",
        "booking_ref": row["vendor_ref"] or "-",
        "extras": f"Requested: {', '.join(flags)}." if flags else "",
    }


def handle_book_service(step: dict) -> None:
    client = VendorClient()
    try:
        resp = client.create_booking(str(step["id"]), step["params"])
    except TransientVendorError as e:
        wfe.schedule_retry(step["workflow_id"], step["id"], step["attempt"], str(e))
        return
    except PermanentVendorError as e:
        wfe.finish_step(step["workflow_id"], step["id"], "FAILED", str(e))
        return
    with tx() as conn:
        q(conn, """INSERT INTO vendor_bookings (id, step_id, vendor, vendor_ref, status, status_rank)
                   VALUES (:id, :s, :v, :ref, 'REQUESTED', 10)
                   ON CONFLICT (step_id) DO UPDATE SET vendor_ref = COALESCE(vendor_bookings.vendor_ref, EXCLUDED.vendor_ref)""",
          id=uuid.uuid4(), s=step["id"], v=client.name, ref=resp["booking_ref"])
        wfe.add_event(conn, step["workflow_id"], "VENDOR_REQUESTED", {"booking_ref": resp["booking_ref"]})
    wfe.mark_waiting_external(step["id"])  # no-op if the CONFIRMED webhook already beat us


def handle_notification(step: dict) -> None:
    user = _user(step["user_id"])
    ctx = _booking_context(step["workflow_id"], user)
    try:
        results = router.send(step["id"], user, step["params"]["channels"], step["params"]["template"], ctx)
    except ProviderError as e:
        wfe.schedule_retry(step["workflow_id"], step["id"], step["attempt"], str(e))
        return
    log.info("step %s notifications: %s", step["step_key"], results)
    wfe.finish_step(step["workflow_id"], step["id"], "SUCCEEDED")


HANDLERS = {
    "BOOK_SERVICE": handle_book_service,
    "SEND_NOTIFICATION": handle_notification,
    "SCHEDULE_REMINDER": handle_notification,
}

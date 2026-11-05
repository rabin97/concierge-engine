"""Celery tasks are thin: load state from Postgres, act only if the conditional update wins."""
import logging
from uuid import UUID

from app.agents.pipeline import plan_workflow as run_pipeline
from app.db import q, tx
from app.services import webhooks
from app.services import workflow_engine as wfe
from app.services.vendor_client import TransientVendorError, VendorClient
from app.workers.celery_app import celery_app
from app.workers.handlers import HANDLERS

log = logging.getLogger(__name__)


@celery_app.task(name="plan_workflow", bind=True, max_retries=3, default_retry_delay=5)
def plan_workflow(self, workflow_id: str) -> str:
    try:
        return run_pipeline(UUID(workflow_id))
    except Exception as e:  # LLM throttling, DB blip: retry, the pipeline is idempotent on PLANNING
        log.exception("planning failed for %s", workflow_id)
        raise self.retry(exc=e)


@celery_app.task(name="run_step")
def run_step(step_id: str) -> str:
    step = wfe.claim_step(UUID(step_id))
    if step is None:
        return "not-claimed"  # duplicate message, or the step moved on
    step = dict(step)
    log.info("running %s (%s) attempt %s", step["step_key"], step["type"], step["attempt"])
    try:
        HANDLERS[step["type"]](step)
    except Exception as e:  # unexpected bug: retry with backoff rather than leave it RUNNING
        log.exception("step %s crashed", step_id)
        wfe.schedule_retry(step["workflow_id"], step["id"], step["attempt"], f"crash: {e}")
    return "done"


@celery_app.task(name="process_webhook", bind=True, max_retries=5, default_retry_delay=3)
def process_webhook(self, inbox_id: int) -> str:
    result = webhooks.process_vendor_event(int(inbox_id))
    log.info("webhook %s -> %s", inbox_id, result)
    return result


@celery_app.task(name="cancel_vendor_booking", bind=True, max_retries=5, default_retry_delay=10)
def cancel_vendor_booking(self, booking_id: str) -> str:
    with tx() as conn:
        b = q(conn, "SELECT vendor_ref FROM vendor_bookings WHERE id=:id", id=booking_id).first()
    if not b or not b[0]:
        return "no-ref"
    try:
        VendorClient().cancel_booking(b[0])
    except TransientVendorError as e:
        raise self.retry(exc=e)
    return "cancel-requested"

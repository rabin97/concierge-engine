import json
import logging
import time
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import PlainTextResponse

from app.agents.guard import service as guard
from app.api.deps import current_user
from app.config import settings
from app.db import q, tx
from app.schemas.api import AnswerRequest, IntentAccepted, IntentRequest, PreferenceIn, WorkflowView
from app.services import preferences, webhooks
from app.services import workflow_engine as wfe
from app.services.vendor_client import verify_signature
from app.workers.celery_app import celery_app

log = logging.getLogger(__name__)
router = APIRouter()


# ------------------------------------------------------------------ intents & workflows
@router.post("/v1/intents", status_code=202, response_model=IntentAccepted)
def submit_intent(body: IntentRequest, request: Request, response: Response, user=Depends(current_user),
                  idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=8, max_length=100)):
    # Blocked prompts raise GuardBlocked (400) and never create a workflow. Only the masked text is stored.
    g = guard.screen_user_text(body.prompt, user_id=user["id"], ip=_client_ip(request))
    wf_id, status, created = wfe.create_workflow(user["id"], idempotency_key, g.safe_text, guard.event_data(g))
    if not created:
        response.status_code = 200
    return IntentAccepted(workflow_id=wf_id, status=status, poll=f"/v1/workflows/{wf_id}")


@router.get("/v1/workflows/{workflow_id}", response_model=WorkflowView)
def get_workflow(workflow_id: UUID, user=Depends(current_user)):
    view = wfe.get_view(workflow_id, user["id"])
    if view is None:
        raise HTTPException(404, "workflow not found")
    return view


@router.post("/v1/workflows/{workflow_id}/confirm")
def confirm_workflow(workflow_id: UUID, user=Depends(current_user)):
    changed = wfe.confirm(workflow_id, user["id"])
    view = wfe.get_view(workflow_id, user["id"])
    if view is None:
        raise HTTPException(404, "workflow not found")
    return {"changed": changed, "status": view["status"]}


@router.post("/v1/workflows/{workflow_id}/answer")
def answer_question(workflow_id: UUID, body: AnswerRequest, request: Request, user=Depends(current_user)):
    g = guard.screen_user_text(body.answer, user_id=user["id"], ip=_client_ip(request))
    if not wfe.answer(workflow_id, user["id"], g.safe_text):
        raise HTTPException(409, "workflow is not waiting for input")
    return {"status": "PLANNING"}


@router.post("/v1/workflows/{workflow_id}/cancel")
def cancel_workflow(workflow_id: UUID, user=Depends(current_user)):
    status = wfe.cancel(workflow_id, user["id"])
    if status == "NOT_FOUND":
        raise HTTPException(404, "workflow not found")
    return {"status": status}


# ------------------------------------------------------------------ preferences
@router.get("/v1/users/me/preferences")
def get_preferences(user=Depends(current_user)):
    return preferences.list_preferences(user["id"])


@router.put("/v1/users/me/preferences", status_code=201)
def add_preference(body: PreferenceIn, request: Request, user=Depends(current_user)):
    # Preference text is embedded (Bedrock) and retrieved into planning, so it is screened like a prompt.
    g = guard.screen_user_text(body.text, user_id=user["id"], ip=_client_ip(request))
    return preferences.upsert_preference(user["id"], body.category, g.safe_text, body.structured)


# ------------------------------------------------------------------ webhooks
@router.post("/v1/webhooks/vendors/{vendor}")
async def vendor_webhook(vendor: str, request: Request,
                         x_vendor_timestamp: str = Header(...), x_vendor_signature: str = Header(...)):
    raw = await request.body()
    try:
        ts = int(x_vendor_timestamp)
    except ValueError:
        raise HTTPException(400, "bad timestamp")
    if abs(time.time() - ts) > settings.vendor_webhook_tolerance_seconds:
        raise HTTPException(401, "stale timestamp")
    if not verify_signature(settings.vendor_webhook_secret, x_vendor_timestamp, raw, x_vendor_signature):
        raise HTTPException(401, "bad signature")
    payload = json.loads(raw)
    inbox_id, is_new = webhooks.ingest(vendor, payload)
    if is_new:
        # Fast path. If this publish is lost, the reconciler picks up RECEIVED inbox rows.
        celery_app.send_task("process_webhook", kwargs={"inbox_id": inbox_id}, queue="webhook")
    return {"ok": True, "duplicate": not is_new}


@router.get("/v1/webhooks/whatsapp")
def whatsapp_verify(mode: str = Query(alias="hub.mode"), token: str = Query(alias="hub.verify_token"),
                    challenge: str = Query(alias="hub.challenge")):
    if mode == "subscribe" and token == settings.whatsapp_verify_token:
        return Response(content=challenge, media_type="text/plain")
    raise HTTPException(403, "verification failed")


@router.post("/v1/webhooks/whatsapp")
async def whatsapp_status(request: Request):
    """Delivery receipts: sent -> delivered -> read | failed. Production: verify X-Hub-Signature-256 first."""
    body = await request.json()
    updates = 0
    for entry in body.get("entry", []):
        for change in entry.get("changes", []):
            for st in change.get("value", {}).get("statuses", []):
                status = {"delivered": "DELIVERED", "read": "READ", "failed": "FAILED"}.get(st.get("status"))
                if status:
                    with tx() as conn:
                        q(conn, "UPDATE notifications SET status=:s, updated_at=now() WHERE provider_msg_id=:p",
                          s=status, p=st.get("id"))
                    updates += 1
    return {"ok": True, "updates": updates}


@router.get("/internal/guard/metrics", include_in_schema=False)
def guard_metrics():
    """Guard counters and latency for this process, in Prometheus text format."""
    return PlainTextResponse(guard.get_pipeline().metrics.render_prometheus())


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/healthz")
def healthz():
    with tx() as conn:
        q(conn, "SELECT 1")
    return {"ok": True}

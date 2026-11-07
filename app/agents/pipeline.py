"""The multi-agent pipeline that runs inside the `plan_workflow` Celery task.

intent agent (LLM) -> output guard -> schema check + repair -> context agent (pgvector) -> time resolver
-> planner -> rule validator -> action guard -> clarifier

The input guard already ran in the API: prompt_redacted is screened, PII-masked text.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone
from uuid import UUID

from pydantic import ValidationError

from app.agents.llm import SYSTEM_PROMPT, get_llm
from app.agents.planner import PlanContext, compile_plan, validate_rules
from app.agents.time_resolver import TimeResolutionError
from app.config import settings
from app.db import q, tx
from app.agents.guard import service as guard
from app.schemas.intent import IntentExtraction
from app.services import preferences
from app.services import workflow_engine as wfe

log = logging.getLogger(__name__)
MAX_REPAIRS = 2


def extract_with_repair(prompt: str) -> IntentExtraction:
    llm = get_llm()
    errors: list[str] | None = None
    for attempt in range(MAX_REPAIRS + 1):
        raw = llm.extract(prompt, repair_errors=errors)
        guard.screen_llm_output(raw, SYSTEM_PROMPT)  # canary / prompt leak: give up, don't repair
        try:
            return IntentExtraction.model_validate(raw)
        except ValidationError as e:
            errors = [f"{'.'.join(map(str, err['loc']))}: {err['msg']}" for err in e.errors()]
            log.warning("intent extraction failed validation (attempt %s): %s", attempt + 1, errors)
    raise ValueError("could not extract a valid intent after repairs")


def plan_workflow(workflow_id: UUID, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    with tx() as conn:
        wf = q(conn, """SELECT w.id, w.user_id, w.prompt_redacted, w.status, u.timezone, u.wa_opt_in_at,
                               (SELECT id FROM addresses a WHERE a.user_id=u.id ORDER BY is_default DESC LIMIT 1) AS address_id
                        FROM workflows w JOIN users u ON u.id = w.user_id WHERE w.id=:id""",
               id=workflow_id).mappings().first()
    if wf is None or wf["status"] != "PLANNING":
        return wf["status"] if wf else "MISSING"  # duplicate delivery: already planned

    prompt = wf["prompt_redacted"]
    try:
        extraction = extract_with_repair(prompt)
    except ValueError:
        wfe.set_needs_input(workflow_id, "Sorry, I didn't get that. Could you say what service and when?")
        return "NEEDS_INPUT"

    prefs = preferences.retrieve(wf["user_id"], prompt)
    flags: dict[str, bool] = {}
    for p in prefs:
        flags.update({k: v for k, v in p["structured"].items() if isinstance(v, bool)})

    if wf["address_id"] is None:
        wfe.set_needs_input(workflow_id, "Please add a service address first.")
        return "NEEDS_INPUT"

    ctx = PlanContext(now=now, timezone=wf["timezone"] or settings.default_timezone,
                      address_id=wf["address_id"], preference_flags=flags,
                      whatsapp_opted_in=wf["wa_opt_in_at"] is not None)
    try:
        outcome = compile_plan(extraction, ctx)
    except TimeResolutionError as e:
        wfe.set_needs_input(workflow_id, f"I couldn't work out the time: {e}.")
        return "NEEDS_INPUT"

    if outcome.question:
        wfe.set_needs_input(workflow_id, outcome.question)
        return "NEEDS_INPUT"

    errors = validate_rules(outcome.tree, now)
    if not errors:  # may also force requires_confirmation, so it runs before the plan is hashed
        errors = guard.review_plan(wf["user_id"], workflow_id, outcome.tree).errors
    if errors:
        wfe.set_needs_input(workflow_id, "I can't schedule that: " + "; ".join(errors) + ".")
        return "NEEDS_INPUT"

    canonical = json.dumps(outcome.tree.model_dump(mode="json"), sort_keys=True)
    plan_hash = hashlib.sha256(canonical.encode()).hexdigest()
    return wfe.save_plan(workflow_id, outcome.tree, plan_hash, settings.prompt_version, outcome.summary,
                         used_preferences=[p["text"] for p in prefs if p["structured"]])

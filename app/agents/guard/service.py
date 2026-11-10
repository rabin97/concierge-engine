"""How the app uses the guard. One pipeline per process, with sync helpers for the
FastAPI routes and Celery tasks.

  POST /v1/intents, /answer, /preferences -> screen_user_text(): reject, or keep the masked text
  intent agent (LLM)                      -> system_prompt() adds a canary; screen_llm_output()
  planner output (TaskTree)               -> review_plan(): allowlist, confirmation, per-user limits
"""
from __future__ import annotations

import asyncio
import json
import logging
from functools import lru_cache
from typing import Any
from uuid import UUID

from app.agents.guard.checks import Complete, LLMInjectionClassifier, LLMJudge, make_openai_complete
from app.agents.guard.config import ConfigStore
from app.agents.guard.observability import AuditTrail, ReviewQueue, configure_json_logging
from app.agents.guard.output_guard import ActionGuard, CanaryManager, OutputGuard, PlanReview
from app.agents.guard.pipeline import GuardPipeline
from app.agents.guard.types import GuardDecision, GuardRequest, Verdict
from app.config import settings
from app.db import q, tx
from app.schemas.task_tree import TaskTree

log = logging.getLogger(__name__)

FALLBACK_MESSAGE = "Sorry, I can't help with that request."


class GuardBlocked(Exception):
    """User text the app must not store or act on. The API turns this into a 400."""

    def __init__(self, decision: GuardDecision) -> None:
        self.decision = decision
        super().__init__(decision.user_message or FALLBACK_MESSAGE)

    @property
    def message(self) -> str:
        return str(self)


class LLMOutputBlocked(ValueError):
    """The LLM leaked its prompt or canary. Subclasses ValueError so the planner treats it
    like any other unusable extraction."""


def _llm_complete() -> Complete:
    """gpt-oss (or any model) behind an OpenAI-compatible endpoint, Bedrock by default."""
    from openai import OpenAI

    api_key = settings.guard_llm_api_key or settings.aws_bearer_token_bedrock
    if not api_key:
        raise RuntimeError("the guard LLM needs GUARD_LLM_API_KEY or AWS_BEARER_TOKEN_BEDROCK")
    base_url = settings.guard_llm_base_url or f"https://bedrock-mantle.{settings.aws_region}.api.aws/v1"
    # No SDK retries: the pipeline has its own timeout, circuit breaker and fail-open/closed policy.
    client = OpenAI(api_key=api_key, base_url=base_url, timeout=settings.guard_llm_timeout_ms / 1000,
                    max_retries=0)
    return make_openai_complete(client, settings.guard_llm_model)


def _llm_overrides() -> dict[str, Any]:
    """LLM checks need far more time than the defaults, which are sized for local checks."""
    t = settings.guard_llm_timeout_ms
    checks: dict[str, Any] = {}
    if settings.guard_classifier == "llm":
        checks["classifier"] = {"timeout_ms": t}
    if settings.guard_llm_judge:
        checks["llm_judge"] = {"timeout_ms": t}
    if not checks:
        return {}
    return {"checks": checks, "latency_budget_ms": len(checks) * t + 300}


@lru_cache
def get_pipeline() -> GuardPipeline:
    configure_json_logging()
    if settings.guard_classifier not in ("heuristic", "llm"):
        raise RuntimeError(f"GUARD_CLASSIFIER must be heuristic or llm, not {settings.guard_classifier!r}")
    complete = _llm_complete() if settings.guard_classifier == "llm" or settings.guard_llm_judge else None
    return GuardPipeline(
        ConfigStore(settings.guard_config_path or None, overrides=_llm_overrides() or None),
        classifier=LLMInjectionClassifier(complete, name=settings.guard_llm_model)
        if settings.guard_classifier == "llm" else None,
        judge=LLMJudge(complete) if settings.guard_llm_judge else None,
        secret_key=settings.guard_hmac_key.encode() if settings.guard_hmac_key else None,
        review_queue=ReviewQueue(settings.guard_review_queue_path) if settings.guard_review_queue_path else None,
        audit=AuditTrail(settings.guard_audit_path) if settings.guard_audit_path else None,
    )


@lru_cache
def _canary() -> CanaryManager:
    return CanaryManager()


# ------------------------------------------------------------------ user input
def screen_user_text(text: str, *, user_id: UUID | str, ip: str | None = None) -> GuardDecision:
    """Guard user text before it is stored or sent to the LLM.

    Raises GuardBlocked when the text must not be used. Otherwise returns the decision;
    ``decision.safe_text`` has PII replaced by tokens like <PHONE_1>. All of a user's
    messages share one session, so attacks split across a prompt and its answers are caught.
    """
    req = GuardRequest(text=text, user_id=str(user_id), session_id=f"user:{user_id}", ip=ip)
    d = asyncio.run(get_pipeline().check_input(req))
    if not d.allowed or d.safe_text is None:
        raise GuardBlocked(d)
    return d


def event_data(d: GuardDecision) -> dict[str, Any]:
    """What a workflow event records about the guard decision. No raw text."""
    return {"request_id": d.request_id, "verdict": d.verdict.value, "risk": round(d.risk_score, 3),
            "rule_ids": d.rule_ids, "pii_types": d.pii_types, "config_version": d.config_version}


# ------------------------------------------------------------------ LLM output
def system_prompt(base: str) -> str:
    """The system prompt with this process's canary token in it."""
    return _canary().inject(base)


def screen_llm_output(raw: dict | str, base_system_prompt: str) -> None:
    """Raise LLMOutputBlocked if the model echoed its canary or its system prompt."""
    text = raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False)
    pipe = get_pipeline()
    guard = OutputGuard(pipe.store.get(), system_prompt=system_prompt(base_system_prompt), canary=_canary(),
                        metrics=pipe.metrics, alert_hook=lambda kind, detail: log.warning("guard alert %s %s",
                                                                                          kind, detail))
    if guard.check(text).verdict == Verdict.BLOCK:
        raise LLMOutputBlocked("LLM output failed the output guard")


# ------------------------------------------------------------------ plans
_RECENT_STEPS = """
SELECT count(*) FROM workflows w
CROSS JOIN LATERAL jsonb_array_elements(w.plan->'steps') s
WHERE w.user_id = :u AND w.id <> :wf AND w.plan IS NOT NULL
  AND w.created_at > now() - (:secs * interval '1 second')
  AND s->>'type' = :t
"""


def review_plan(user_id: UUID, workflow_id: UUID, tree: TaskTree) -> PlanReview:
    """Check a validated plan against the action policy. Counts the user's steps from other
    planned workflows in Postgres (cancelled ones included, so book/cancel loops still count).
    May set requires_confirmation on booking steps."""

    def recent(step_type: str, window_s: int) -> int:
        with tx() as conn:
            return q(conn, _RECENT_STEPS, u=user_id, wf=workflow_id, secs=window_s, t=step_type).scalar_one()

    pipe = get_pipeline()
    review = ActionGuard(pipe.store.get(), metrics=pipe.metrics).review_plan(tree, recent)
    if not review.ok:
        log.info("plan for workflow %s denied by guard: %s", workflow_id, review.reasons)
    return review

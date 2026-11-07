from datetime import datetime, timezone
from uuid import uuid4

from app.agents.llm import FakeLLM
from app.agents.planner import PlanContext, compile_plan, validate_rules
from app.agents.time_resolver import resolve_point, resolve_window
from app.schemas.intent import IntentExtraction, PartOfDay, TimeExpr
from app.services.preferences import derive_structured
from app.services.vendor_client import sign, verify_signature

# Wednesday 4 Nov 2026, 09:00 IST
NOW = datetime(2026, 11, 4, 3, 30, tzinfo=timezone.utc)
TZ = "Asia/Kolkata"
PROMPT = "Schedule a deep cleaning service for Saturday morning and remind me on Friday night"


def ctx(flags=None, wa=True):
    return PlanContext(now=NOW, timezone=TZ, address_id=uuid4(), preference_flags=flags or {}, whatsapp_opted_in=wa)


def test_time_resolver_weekday_and_part():
    w = resolve_window(TimeExpr(day="saturday", part_of_day=PartOfDay.MORNING), NOW, TZ)
    assert w.start.isoformat() == "2026-11-07T09:00:00+05:30"
    assert w.end.isoformat() == "2026-11-07T12:00:00+05:30"
    assert resolve_point(TimeExpr(day="friday", part_of_day=PartOfDay.NIGHT), NOW, TZ).isoformat() \
        == "2026-11-06T21:00:00+05:30"


def test_same_weekday_in_the_past_rolls_to_next_week():
    w = resolve_window(TimeExpr(day="wednesday", part_of_day=PartOfDay.MORNING), NOW, TZ)  # 09:00 is now
    assert w.start.isoformat() == "2026-11-11T09:00:00+05:30"


def test_sample_prompt_end_to_end_plan():
    ex = IntentExtraction.model_validate(FakeLLM().extract(PROMPT))
    out = compile_plan(ex, ctx({"eco_products": True}))
    assert out.question is None
    keys = [s.step_key for s in out.tree.steps]
    assert keys == ["book_1", "notify_booked_1", "remind_1"]
    book, _, remind = out.tree.steps
    assert book.params.constraints == {"eco_products": True}
    assert remind.depends_on == ["book_1"]
    assert remind.params.fire_at.isoformat() == "2026-11-06T21:00:00+05:30"
    assert validate_rules(out.tree, NOW) == []


def test_reminder_without_time_defaults_to_night_before():
    ex = IntentExtraction.model_validate(FakeLLM().extract("Book pest control on Sunday afternoon and remind me"))
    out = compile_plan(ex, ctx())
    assert out.tree.steps[-1].params.fire_at.isoformat() == "2026-11-07T21:00:00+05:30"


def test_missing_time_asks_question():
    ex = IntentExtraction.model_validate(FakeLLM().extract("Book a plumber please"))
    assert "When" in compile_plan(ex, ctx()).question


def test_reminder_after_service_is_rejected():
    ex = IntentExtraction.model_validate(FakeLLM().extract("Deep clean on Friday morning and remind me on Saturday night"))
    errors = validate_rules(compile_plan(ex, ctx()).tree, NOW)
    assert "the reminder must be before the service starts" in errors


def test_email_only_when_not_opted_in_to_whatsapp():
    ex = IntentExtraction.model_validate(FakeLLM().extract(PROMPT))
    out = compile_plan(ex, ctx(wa=False))
    assert out.tree.steps[1].params.channels == ["EMAIL"]


def test_preference_flags():
    assert derive_structured("I am allergic to harsh chemicals") == {"eco_products": True}


def test_webhook_signature():
    body = b'{"status":"CONFIRMED"}'
    sig = sign("s3cret", "1700000000", body)
    assert verify_signature("s3cret", "1700000000", body, sig)
    assert not verify_signature("s3cret", "1700000001", body, sig)

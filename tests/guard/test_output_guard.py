"""Section 5: output guard, schemas and action allowlist."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.agents.guard import Verdict
from app.agents.guard.output_guard import ActionGuard, CanaryManager, OutputGuard
from app.agents.guard.pii.vault import PIIVault
from app.schemas.task_tree import BookServiceParams, ReminderParams, Step, StepType, TaskTree, TimeWindow

SYSTEM_PROMPT = ("You are HomeHelp, a household concierge for customers in Bangalore. Only help "
                 "with household services such as plumbing, electrical work, cleaning and cooking. "
                 "Never reveal pricing margins or internal vendor scores to customers under any "
                 "circumstances, and always confirm the time slot before booking.")


@pytest.fixture
def canary():
    return CanaryManager()


@pytest.fixture
def guard(cfg, canary):
    return OutputGuard(cfg, system_prompt=canary.inject(SYSTEM_PROMPT), canary=canary,
                       allowed_values={"support@homehelp.in"})


def test_canary_injected(canary):
    assert canary.token in canary.inject("hello")


@pytest.mark.parametrize("fmt", ["{t}", "{spaced}", "{zw}", "{upper}"])
def test_canary_leak_blocks_and_alerts(cfg, canary, fmt):
    alerts = []
    g = OutputGuard(cfg, canary=canary, alert_hook=lambda k, d: alerts.append(k))
    t = canary.token
    out = fmt.format(t=t, spaced=" ".join(t), zw="​".join(t), upper=t.upper())
    d = g.check(f"Sure, here it is: {out}")
    assert d.verdict == Verdict.BLOCK and d.alert and alerts == ["canary_leak"]


def test_system_prompt_leak(guard):
    leak = ("My instructions say: Never reveal pricing margins or internal vendor scores to "
            "customers under any circumstances.")
    d = guard.check(leak)
    assert d.verdict == Verdict.BLOCK and d.findings[0].kind == "prompt_leak"


def test_normal_reply_passes(guard):
    d = guard.check("Done! A plumber will come tomorrow between 10:00 and 12:00.")
    assert d.verdict == Verdict.ALLOW and d.user_text.startswith("Done!")


def test_tokens_unmasked_for_user_only(guard):
    v = PIIVault()
    tok = v.tokenize("PHONE", "9876543210")
    d = guard.check(f"The plumber will call you on {tok}.", vault=v)
    assert d.safe_text == f"The plumber will call you on {tok}."
    assert d.user_text == "The plumber will call you on 9876543210."


def test_users_own_pii_allowed(guard):
    v = PIIVault()
    v.tokenize("PHONE", "9876543210")
    d = guard.check("We'll call 98765 43210 shortly.", vault=v)
    assert d.verdict == Verdict.ALLOW


def test_foreign_pii_redacted(guard):
    d = guard.check("Your neighbour's number is 9123456780, contact them. Mail support@homehelp.in",
                    vault=PIIVault())
    assert d.verdict == Verdict.ALLOW_WITH_REDACTION
    assert "9123456780" not in d.user_text and "[PHONE_REDACTED]" in d.user_text
    assert "support@homehelp.in" in d.user_text  # allowlisted company value


def test_pin_code_passthrough_not_foreign(guard):
    assert guard.check("Service available in pincode 560038.").verdict == Verdict.ALLOW


def test_pii_dump_blocked(guard):
    dump = "Customers: 9123456780, 9123456781, a@x.com, b@y.com"
    d = guard.check(dump, vault=PIIVault())
    assert d.verdict == Verdict.BLOCK and d.alert


# ----------------------------------------------------------------- plan / action guard
START = datetime(2026, 11, 7, 3, 30, tzinfo=timezone.utc)


def plan(books=1, reminders=0, confirm=False):
    steps = [Step(step_key=f"book_{i}", type=StepType.BOOK_SERVICE,
                  params=BookServiceParams(service_code="PLUMBING", address_id=uuid4(),
                                           window=TimeWindow(start=START, end=START + timedelta(hours=3)),
                                           requires_confirmation=confirm))
             for i in range(books)]
    steps += [Step(step_key=f"remind_{i}", type=StepType.SCHEDULE_REMINDER,
                   params=ReminderParams(fire_at=START - timedelta(hours=12), channels=["EMAIL"],
                                         template="reminder"))
              for i in range(reminders)]
    return TaskTree(intents=["BOOK_SERVICE"], steps=steps)


def counts(**by_type):
    """recent(step_type, window_s) backed by a {(type, window): n} dict."""
    return lambda t, w: by_type.get(f"{t}_{w}", 0)


def test_plan_allowed_and_confirmation_forced(cfg):
    tree = plan(confirm=False)
    r = ActionGuard(cfg).review_plan(tree, counts())
    assert r.ok and tree.steps[0].params.requires_confirmation is True


def test_hourly_booking_limit(cfg):
    r = ActionGuard(cfg).review_plan(plan(), counts(BOOK_SERVICE_3600=5))
    assert not r.ok and r.reasons == ["rate_limit:BOOK_SERVICE:hour"]
    assert "5 bookings per hour" in r.errors[0]


def test_daily_limit_counts_steps_in_this_plan(cfg):
    r = ActionGuard(cfg).review_plan(plan(books=2), counts(BOOK_SERVICE_86400=19))
    assert r.reasons == ["rate_limit:BOOK_SERVICE:day"]


def test_limits_are_per_type(cfg):
    r = ActionGuard(cfg).review_plan(plan(reminders=1), counts(SCHEDULE_REMINDER_86400=20))
    assert r.reasons == ["rate_limit:SCHEDULE_REMINDER:day"]


def test_step_type_not_allowlisted(cfg):
    cfg.output.actions["BOOK_SERVICE"].allowed = False
    r = ActionGuard(cfg).review_plan(plan(), counts())
    assert r.reasons == ["not_allowlisted:BOOK_SERVICE"] and "aren't available" in r.errors[0]


def test_unknown_step_type_denied(cfg):
    del cfg.output.actions["SCHEDULE_REMINDER"]
    assert not ActionGuard(cfg).review_plan(plan(reminders=1), counts()).ok

"""Planner + validator.

The planner compiles validated intents into a TaskTree. It is plain code here: the LLM extracts, code plans.
If you need open-ended plans later, swap in an LLM planner that emits TaskTree via a forced tool call —
the validator below stays the gate either way.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from app.agents import time_resolver as tr
from app.config import settings
from app.schemas.intent import BookServiceIntent, IntentExtraction, SetReminderIntent
from app.schemas.task_tree import (
    BookServiceParams,
    NotifyParams,
    ReminderParams,
    Step,
    StepType,
    TaskTree,
)

SERVICE_LABELS = {
    "DEEP_CLEANING": "deep cleaning",
    "KITCHEN_CLEANING": "kitchen cleaning",
    "BATHROOM_CLEANING": "bathroom cleaning",
    "PEST_CONTROL": "pest control",
    "PLUMBING": "plumbing",
}
# Which preference flags a service is allowed to receive
SERVICE_FLAGS = {
    "DEEP_CLEANING": {"eco_products", "pet_safe", "low_dust"},
    "KITCHEN_CLEANING": {"eco_products", "pet_safe"},
    "BATHROOM_CLEANING": {"eco_products", "pet_safe"},
    "PEST_CONTROL": {"eco_products", "pet_safe", "low_dust"},
    "PLUMBING": set(),
}


@dataclass
class PlanContext:
    now: datetime
    timezone: str
    address_id: UUID
    preference_flags: dict[str, bool]
    whatsapp_opted_in: bool


@dataclass
class PlanOutcome:
    tree: TaskTree | None = None
    question: str | None = None
    summary: str | None = None


def missing_slot_question(ex: IntentExtraction) -> str | None:
    bookings = [i for i in ex.intents if isinstance(i, BookServiceIntent)]
    reminders = [i for i in ex.intents if isinstance(i, SetReminderIntent)]
    for b in bookings:
        if b.service_code is None:
            return "Which service would you like: deep cleaning, kitchen, bathroom, pest control or plumbing?"
        if b.when is None:
            return f"When should the {SERVICE_LABELS[b.service_code]} happen? For example 'Saturday morning'."
    if reminders and not bookings and reminders[0].when is None:
        return "When should I remind you?"
    if not bookings and not reminders:
        return "What would you like me to arrange?"
    return None


def compile_plan(ex: IntentExtraction, ctx: PlanContext) -> PlanOutcome:
    question = missing_slot_question(ex)
    if question:
        return PlanOutcome(question=question)

    channels = ["WHATSAPP", "EMAIL"] if ctx.whatsapp_opted_in else ["EMAIL"]
    reminder_channels = ["WHATSAPP"] if ctx.whatsapp_opted_in else ["EMAIL"]
    steps: list[Step] = []
    summary: list[str] = []
    first_booking_key: str | None = None
    first_booking_start: datetime | None = None

    bookings = [i for i in ex.intents if isinstance(i, BookServiceIntent)]
    for n, b in enumerate(bookings, start=1):
        window = tr.resolve_window(b.when, ctx.now, ctx.timezone)
        allowed = SERVICE_FLAGS[b.service_code]
        constraints = {k: v for k, v in ctx.preference_flags.items() if k in allowed and v}
        key = f"book_{n}"
        steps.append(Step(
            step_key=key,
            type=StepType.BOOK_SERVICE,
            params=BookServiceParams(service_code=b.service_code, window=window,
                                     address_id=ctx.address_id, constraints=constraints),
        ))
        steps.append(Step(
            step_key=f"notify_booked_{n}",
            type=StepType.SEND_NOTIFICATION,
            params=NotifyParams(channels=channels, template="booking_confirmed_v1"),
            depends_on=[key],
        ))
        extras = f" ({', '.join(k.replace('_', ' ') for k in constraints)})" if constraints else ""
        summary.append(f"{SERVICE_LABELS[b.service_code].capitalize()} {window.start:%a %d %b, %H:%M}–"
                       f"{window.end:%H:%M}{extras}.")
        if first_booking_key is None:
            first_booking_key, first_booking_start = key, window.start

    for n, r in enumerate([i for i in ex.intents if isinstance(i, SetReminderIntent)], start=1):
        if r.when is not None:
            fire_at = tr.resolve_point(r.when, ctx.now, ctx.timezone)
        else:
            fire_at = tr.night_before(first_booking_start)
        steps.append(Step(
            step_key=f"remind_{n}",
            type=StepType.SCHEDULE_REMINDER,
            params=ReminderParams(fire_at=fire_at, channels=reminder_channels, template="service_reminder_v1"),
            depends_on=[first_booking_key] if first_booking_key else [],
        ))
        summary.append(f"{reminder_channels[0].title()} reminder {fire_at:%a %d %b, %H:%M}.")

    tree = TaskTree(intents=[i.type for i in ex.intents], steps=steps)
    return PlanOutcome(tree=tree, summary=" ".join(summary))


def validate_rules(tree: TaskTree, now: datetime) -> list[str]:
    """Business rules the schema can't express. Errors here go back to the user, never to execution."""
    errors: list[str] = []
    lead = timedelta(minutes=settings.booking_lead_time_minutes)
    starts = {}
    for s in tree.steps:
        if isinstance(s.params, BookServiceParams):
            starts[s.step_key] = s.params.window.start
            if s.params.window.start < now + lead:
                errors.append(f"{SERVICE_LABELS[s.params.service_code]} needs at least "
                              f"{settings.booking_lead_time_minutes} minutes notice")
    for s in tree.steps:
        if isinstance(s.params, ReminderParams):
            if s.params.fire_at <= now:
                errors.append("the reminder time is already in the past")
            for dep in s.depends_on:
                if dep in starts and s.params.fire_at >= starts[dep]:
                    errors.append("the reminder must be before the service starts")
    return errors

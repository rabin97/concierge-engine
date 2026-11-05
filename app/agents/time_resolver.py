"""Time resolver (no LLM): turns 'saturday' + MORNING into an absolute window in the user's time zone."""
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from app.schemas.intent import PartOfDay, TimeExpr
from app.schemas.task_tree import TimeWindow

WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
# Service windows for each part of day (start hour, end hour)
SERVICE_WINDOWS = {
    PartOfDay.MORNING: (9, 12),
    PartOfDay.AFTERNOON: (13, 16),
    PartOfDay.EVENING: (17, 20),
    PartOfDay.NIGHT: (19, 21),
}
# When a reminder fires for each part of day
REMINDER_HOURS = {PartOfDay.MORNING: 9, PartOfDay.AFTERNOON: 14, PartOfDay.EVENING: 18, PartOfDay.NIGHT: 21}
DEFAULT_SERVICE_HOURS = 3


class TimeResolutionError(ValueError):
    pass


def _candidate_date(day: str, now_local: datetime) -> date:
    d = day.lower().strip()
    today = now_local.date()
    if d == "today":
        return today
    if d == "tomorrow":
        return today + timedelta(days=1)
    if d in WEEKDAYS:
        ahead = (WEEKDAYS.index(d) - today.weekday()) % 7
        return today + timedelta(days=ahead)
    try:
        return date.fromisoformat(d)
    except ValueError as e:
        raise TimeResolutionError(f"cannot understand day '{day}'") from e


def _roll_forward_if_past(expr: TimeExpr, start: datetime, now_local: datetime) -> datetime:
    # "saturday" said on a Saturday afternoon about the morning means next Saturday
    if start <= now_local and expr.day.lower() in WEEKDAYS:
        return start + timedelta(days=7)
    return start


def resolve_window(expr: TimeExpr, now: datetime, tz: str) -> TimeWindow:
    zone = ZoneInfo(tz)
    now_local = now.astimezone(zone)
    d = _candidate_date(expr.day, now_local)
    if expr.time:
        hh, mm = map(int, expr.time.split(":"))
        start = datetime.combine(d, time(hh, mm), zone)
        end = start + timedelta(hours=DEFAULT_SERVICE_HOURS)
    else:
        part = expr.part_of_day or PartOfDay.MORNING
        sh, eh = SERVICE_WINDOWS[part]
        start = datetime.combine(d, time(sh), zone)
        end = datetime.combine(d, time(eh), zone)
    shifted = _roll_forward_if_past(expr, start, now_local)
    end += shifted - start
    return TimeWindow(start=shifted, end=end)


def resolve_point(expr: TimeExpr, now: datetime, tz: str) -> datetime:
    zone = ZoneInfo(tz)
    now_local = now.astimezone(zone)
    d = _candidate_date(expr.day, now_local)
    if expr.time:
        hh, mm = map(int, expr.time.split(":"))
    else:
        hh, mm = REMINDER_HOURS[expr.part_of_day or PartOfDay.EVENING], 0
    point = datetime.combine(d, time(hh, mm), zone)
    return _roll_forward_if_past(expr, point, now_local)


def night_before(window_start: datetime) -> datetime:
    prev = window_start - timedelta(days=1)
    return prev.replace(hour=REMINDER_HOURS[PartOfDay.NIGHT], minute=0, second=0, microsecond=0)

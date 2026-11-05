"""One template name, two renderings. WhatsApp templates must be pre-approved in Meta Business Manager
under the UTILITY category with the same variable order as `wa_params` below."""
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Template:
    wa_name: str
    wa_params: Callable[[dict], list[str]]
    email_subject: Callable[[dict], str]
    email_body: Callable[[dict], str]


TEMPLATES: dict[str, Template] = {
    "booking_confirmed_v1": Template(
        wa_name="booking_confirmed_v1",
        wa_params=lambda c: [c["name"], c["service"], c["when"], c["booking_ref"]],
        email_subject=lambda c: f"Your {c['service']} is booked for {c['when']}",
        email_body=lambda c: (f"Hi {c['name']},\n\nYour {c['service']} is confirmed for {c['when']}.\n"
                              f"Booking reference: {c['booking_ref']}\n{c['extras']}\n\nThanks!"),
    ),
    "service_reminder_v1": Template(
        wa_name="service_reminder_v1",
        wa_params=lambda c: [c["name"], c["service"], c["when"]],
        email_subject=lambda c: f"Reminder: {c['service']} {c['when']}",
        email_body=lambda c: f"Hi {c['name']},\n\nA reminder that your {c['service']} is scheduled for {c['when']}.",
    ),
    "booking_failed_v1": Template(
        wa_name="booking_failed_v1",
        wa_params=lambda c: [c["name"], c["service"]],
        email_subject=lambda c: f"We couldn't book your {c['service']}",
        email_body=lambda c: f"Hi {c['name']},\n\nWe couldn't confirm your {c['service']}. Please try another slot.",
    ),
}

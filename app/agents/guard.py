"""Guard agent (no LLM): limits, injection heuristics, PII masking before anything leaves the app."""
import re
from dataclasses import dataclass

PHONE = re.compile(r"(?:\+?91[\s-]?)?[6-9]\d{9}\b")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PINCODE = re.compile(r"\b[1-9]\d{5}\b")
INJECTION = re.compile(r"ignore (all|previous) instructions|system prompt|you are now", re.I)


@dataclass
class GuardResult:
    redacted: str
    blocked_reason: str | None = None


def guard(prompt: str) -> GuardResult:
    text = " ".join(prompt.split())
    if len(text) > 1000:
        return GuardResult(text[:1000], "prompt too long")
    if INJECTION.search(text):
        return GuardResult(text, "prompt looks like an instruction to the system, not a household request")
    text = EMAIL.sub("<EMAIL>", text)
    text = PHONE.sub("<PHONE>", text)
    text = PINCODE.sub("<PINCODE>", text)
    return GuardResult(text)

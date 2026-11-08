"""Intent agent. Two providers behind one interface:

- FakeLLM: deterministic rules, runs offline, good enough for the demo prompts and for tests.
- BedrockLLM: Amazon Bedrock Converse API with a forced tool call, so the model can only answer
  with JSON that matches IntentExtraction's schema.
"""
import json
import re
from typing import Protocol

from app.agents.guard import service as guard
from app.config import settings
from app.schemas.intent import IntentExtraction

SYSTEM_PROMPT = """You extract household-service intents from a user's message.
Return ONLY a call to the emit_intents tool.
Rules:
- Supported services: DEEP_CLEANING, KITCHEN_CLEANING, BATHROOM_CLEANING, PEST_CONTROL, PLUMBING.
- Never compute dates. Copy the user's day words: today, tomorrow, a weekday name, or an ISO date.
- part_of_day is MORNING, AFTERNOON, EVENING or NIGHT when the user implies one.
- time is 24h HH:MM only if the user states a clock time.
- If something is missing, leave that field null. Do not guess.
"""


class LLMClient(Protocol):
    def extract(self, prompt: str, repair_errors: list[str] | None = None) -> dict: ...


# ---------------------------------------------------------------- fake provider
SERVICES = [
    (r"deep\s*clean", "DEEP_CLEANING"),
    (r"kitchen", "KITCHEN_CLEANING"),
    (r"bathroom|toilet", "BATHROOM_CLEANING"),
    (r"pest|cockroach|termite", "PEST_CONTROL"),
    (r"plumb|leak|tap", "PLUMBING"),
    (r"clean", "DEEP_CLEANING"),
]
DAY = r"(today|tonight|tomorrow|monday|tuesday|wednesday|thursday|friday|saturday|sunday|\d{4}-\d{2}-\d{2})"
PART = r"(morning|afternoon|evening|night|tonight)"
CLOCK = r"(\d{1,2})(?::(\d{2}))?\s*(am|pm)"


def _time_expr(fragment: str) -> dict | None:
    f = fragment.lower()
    day = re.search(DAY, f)
    if not day:
        return None
    d = day.group(1)
    expr: dict = {"day": "today" if d == "tonight" else d}
    part = re.search(PART, f)
    if part:
        p = part.group(1)
        expr["part_of_day"] = "NIGHT" if p == "tonight" else p.upper()
    elif d == "tonight":
        expr["part_of_day"] = "NIGHT"
    clock = re.search(CLOCK, f)
    if clock:
        h = int(clock.group(1)) % 12 + (12 if clock.group(3) == "pm" else 0)
        expr["time"] = f"{h:02d}:{int(clock.group(2) or 0):02d}"
    return expr


class FakeLLM:
    def extract(self, prompt: str, repair_errors: list[str] | None = None) -> dict:
        text = prompt.lower()
        booking_part, _, reminder_part = text.partition("remind")
        intents: list[dict] = []
        service = next((code for pat, code in SERVICES if re.search(pat, booking_part)), None)
        if service or re.search(r"book|schedule|service", booking_part):
            intents.append({"type": "BOOK_SERVICE", "service_code": service, "when": _time_expr(booking_part)})
        if reminder_part:
            intents.append({"type": "SET_REMINDER", "when": _time_expr(reminder_part)})
        return {"intents": intents}


# ---------------------------------------------------------------- bedrock provider
class BedrockLLM:
    def __init__(self) -> None:
        import boto3

        if not settings.bedrock_model_id:
            raise RuntimeError("BEDROCK_MODEL_ID must be set when LLM_PROVIDER=bedrock")
        self.client = boto3.client("bedrock-runtime", region_name=settings.aws_region)
        self.tool = {
            "toolSpec": {
                "name": "emit_intents",
                "description": "Emit the intents found in the user's household request.",
                "inputSchema": {"json": IntentExtraction.model_json_schema()},
            }
        }

    def extract(self, prompt: str, repair_errors: list[str] | None = None) -> dict:
        user_text = prompt
        if repair_errors:
            user_text += "\n\nYour previous answer failed validation:\n- " + "\n- ".join(repair_errors)
        resp = self.client.converse(
            modelId=settings.bedrock_model_id,
            system=[{"text": guard.system_prompt(SYSTEM_PROMPT)}],  # carries the canary
            messages=[{"role": "user", "content": [{"text": user_text}]}],
            toolConfig={"tools": [self.tool], "toolChoice": {"tool": {"name": "emit_intents"}}},
            inferenceConfig={"temperature": 0, "maxTokens": 800},
        )
        for block in resp["output"]["message"]["content"]:
            if "toolUse" in block:
                data = block["toolUse"]["input"]
                return data if isinstance(data, dict) else json.loads(data)
        raise ValueError("model did not call emit_intents")


def get_llm() -> LLMClient:
    return BedrockLLM() if settings.llm_provider == "bedrock" else FakeLLM()

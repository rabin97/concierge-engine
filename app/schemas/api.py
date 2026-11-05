from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class IntentRequest(BaseModel):
    prompt: str = Field(min_length=3, max_length=1000)


class IntentAccepted(BaseModel):
    workflow_id: UUID
    status: str
    poll: str


class AnswerRequest(BaseModel):
    answer: str = Field(min_length=1, max_length=500)


class PreferenceIn(BaseModel):
    category: str = Field(pattern=r"^(HEALTH|SCHEDULE|PRODUCT|CHANNEL|OTHER)$")
    text: str = Field(min_length=3, max_length=300)
    structured: dict[str, Any] | None = None


class StepView(BaseModel):
    step_key: str
    type: str
    status: str
    attempt: int
    last_error: str | None = None


class WorkflowView(BaseModel):
    workflow_id: UUID
    status: str
    summary: str | None
    question: str | None
    plan: dict | None
    steps: list[StepView]
    booking: dict | None
    notifications: list[dict]
    events: list[dict]

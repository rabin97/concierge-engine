"""The contract between the LLM side and the execution side.

Nothing executes unless it parses as a TaskTree. The DAG check, discriminated params and
timezone-aware datetimes make an invalid plan fail here, not halfway through a booking.
"""
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal, Union
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

ServiceCode = Literal["DEEP_CLEANING", "KITCHEN_CLEANING", "BATHROOM_CLEANING", "PEST_CONTROL", "PLUMBING"]
Channel = Literal["WHATSAPP", "EMAIL"]


class StepType(str, Enum):
    BOOK_SERVICE = "BOOK_SERVICE"
    SEND_NOTIFICATION = "SEND_NOTIFICATION"
    SCHEDULE_REMINDER = "SCHEDULE_REMINDER"


def _aware(v: datetime) -> datetime:
    if v.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return v


class TimeWindow(BaseModel):
    start: datetime
    end: datetime

    _check_tz = field_validator("start", "end")(_aware)

    @model_validator(mode="after")
    def ordered(self):
        if self.end <= self.start:
            raise ValueError("window end must be after start")
        return self


class BookServiceParams(BaseModel):
    kind: Literal["BOOK_SERVICE"] = "BOOK_SERVICE"
    service_code: ServiceCode
    window: TimeWindow
    address_id: UUID
    constraints: dict[str, bool] = {}
    requires_confirmation: bool = True


class ReminderParams(BaseModel):
    kind: Literal["SCHEDULE_REMINDER"] = "SCHEDULE_REMINDER"
    fire_at: datetime
    channels: list[Channel] = Field(min_length=1)
    template: str

    _check_tz = field_validator("fire_at")(_aware)


class NotifyParams(BaseModel):
    kind: Literal["SEND_NOTIFICATION"] = "SEND_NOTIFICATION"
    channels: list[Channel] = Field(min_length=1)
    template: str


Params = Annotated[Union[BookServiceParams, ReminderParams, NotifyParams], Field(discriminator="kind")]


class Step(BaseModel):
    step_key: str = Field(pattern=r"^[a-z0-9_]{2,40}$")
    type: StepType
    params: Params
    depends_on: list[str] = []
    run_condition: Literal["ON_SUCCESS", "ALWAYS"] = "ON_SUCCESS"

    @model_validator(mode="after")
    def params_match_type(self):
        if self.params.kind != self.type.value:
            raise ValueError(f"step {self.step_key}: params.kind {self.params.kind} != type {self.type.value}")
        return self


class TaskTree(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    intents: list[str]
    steps: list[Step] = Field(min_length=1, max_length=10)

    @model_validator(mode="after")
    def valid_dag(self):
        keys = [s.step_key for s in self.steps]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate step_key")
        keyset = set(keys)
        for s in self.steps:
            missing = set(s.depends_on) - keyset
            if missing:
                raise ValueError(f"{s.step_key} depends on unknown {sorted(missing)}")
        # Kahn's algorithm: anything left over is in a cycle
        indeg = {s.step_key: len(s.depends_on) for s in self.steps}
        ready = [k for k, d in indeg.items() if d == 0]
        seen = 0
        while ready:
            k = ready.pop()
            seen += 1
            for s in self.steps:
                if k in s.depends_on:
                    indeg[s.step_key] -= 1
                    if indeg[s.step_key] == 0:
                        ready.append(s.step_key)
        if seen != len(self.steps):
            raise ValueError("task tree contains a cycle")
        return self

    def needs_confirmation(self) -> bool:
        return any(isinstance(s.params, BookServiceParams) and s.params.requires_confirmation for s in self.steps)

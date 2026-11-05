"""What the LLM is allowed to return: intents + raw slots. Never absolute timestamps — time math is code."""
from enum import Enum
from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field

from app.schemas.task_tree import ServiceCode


class PartOfDay(str, Enum):
    MORNING = "MORNING"
    AFTERNOON = "AFTERNOON"
    EVENING = "EVENING"
    NIGHT = "NIGHT"


class TimeExpr(BaseModel):
    day: str = Field(description="today | tomorrow | monday..sunday | YYYY-MM-DD")
    part_of_day: PartOfDay | None = None
    time: str | None = Field(default=None, pattern=r"^\d{2}:\d{2}$", description="24h HH:MM if stated")


class BookServiceIntent(BaseModel):
    type: Literal["BOOK_SERVICE"] = "BOOK_SERVICE"
    service_code: ServiceCode | None = None
    when: TimeExpr | None = None


class SetReminderIntent(BaseModel):
    type: Literal["SET_REMINDER"] = "SET_REMINDER"
    when: TimeExpr | None = None


Intent = Annotated[Union[BookServiceIntent, SetReminderIntent], Field(discriminator="type")]


class IntentExtraction(BaseModel):
    intents: list[Intent] = Field(min_length=1, max_length=5)

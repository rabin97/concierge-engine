from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.task_tree import TaskTree

NOW = datetime(2026, 11, 4, 3, 30, tzinfo=timezone.utc)


def booking(key="book_1", deps=None):
    return {"step_key": key, "type": "BOOK_SERVICE", "depends_on": deps or [],
            "params": {"kind": "BOOK_SERVICE", "service_code": "DEEP_CLEANING", "address_id": str(uuid4()),
                       "window": {"start": (NOW + timedelta(days=3)).isoformat(),
                                  "end": (NOW + timedelta(days=3, hours=3)).isoformat()}}}


def notify(key, deps):
    return {"step_key": key, "type": "SEND_NOTIFICATION", "depends_on": deps,
            "params": {"kind": "SEND_NOTIFICATION", "channels": ["WHATSAPP"], "template": "booking_confirmed_v1"}}


def test_valid_tree():
    tree = TaskTree.model_validate({"intents": ["BOOK_SERVICE"], "steps": [booking(), notify("n_1", ["book_1"])]})
    assert tree.needs_confirmation()


def test_unknown_dependency_rejected():
    with pytest.raises(ValidationError, match="unknown"):
        TaskTree.model_validate({"intents": ["X"], "steps": [notify("n_1", ["nope"])]})


def test_cycle_rejected():
    with pytest.raises(ValidationError, match="cycle"):
        TaskTree.model_validate({"intents": ["X"], "steps": [booking("aa", ["bb"]), notify("bb", ["aa"])]})


def test_params_must_match_type():
    bad = notify("n_1", [])
    bad["type"] = "BOOK_SERVICE"
    with pytest.raises(ValidationError):
        TaskTree.model_validate({"intents": ["X"], "steps": [bad]})


def test_naive_datetime_rejected():
    b = booking()
    b["params"]["window"]["start"] = "2026-11-07T09:00:00"
    with pytest.raises(ValidationError, match="timezone"):
        TaskTree.model_validate({"intents": ["X"], "steps": [b]})


def test_unknown_service_rejected():
    b = booking()
    b["params"]["service_code"] = "CAR_WASH"
    with pytest.raises(ValidationError):
        TaskTree.model_validate({"intents": ["X"], "steps": [b]})

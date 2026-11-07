import asyncio
import warnings

import pytest

from app.agents.guard import load_config
from app.agents.guard.pipeline import GuardPipeline
from app.agents.guard import GuardRequest

warnings.filterwarnings("ignore", message="GUARD_HMAC_KEY")


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def cfg():
    return load_config()


@pytest.fixture
def pipeline(cfg):
    return GuardPipeline(cfg, secret_key=b"test-key")


@pytest.fixture
def check(pipeline):
    def _check(text, **kw):
        return run(pipeline.check_input(GuardRequest(text=text, **kw)))
    return _check

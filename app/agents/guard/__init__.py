"""app.agents.guard: input/output guard for an AI household concierge."""
import logging

from .config import ConfigStore, GuardConfig, load_config
from .normalize import NormalizedText, normalize
from .output_guard import ActionGuard, CanaryManager, OutputGuard
from .pipeline import GuardPipeline, build_default_pipeline, wrap_untrusted
from .types import CheckResult, GuardDecision, GuardRequest, Source, Verdict

logging.getLogger("app.agents.guard").addHandler(logging.NullHandler())

__version__ = "0.1.0"
__all__ = [
    "ActionGuard", "CanaryManager", "CheckResult", "ConfigStore", "GuardConfig", "GuardDecision",
    "GuardPipeline", "GuardRequest", "NormalizedText", "OutputGuard", "Source", "Verdict",
    "build_default_pipeline", "load_config", "normalize", "wrap_untrusted",
]

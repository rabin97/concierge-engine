"""Section 8: config-driven thresholds, patterns and per-tenant policies, with hot
reload and versioning. Every decision records the config version that made it."""
from __future__ import annotations

import copy
import hashlib
import os
import threading
import time
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, model_validator

from .types import OnError

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config" / "default.yaml"


class Thresholds(BaseModel):
    flag: float = 0.45
    block: float = 0.80
    judge_low: float = 0.30  # LLM judge only runs when risk is in [judge_low, block)
    judge_high: float = 0.80

    @model_validator(mode="after")
    def _ordered(self) -> "Thresholds":
        if not (0 <= self.flag <= self.block <= 1):
            raise ValueError("need 0 <= flag <= block <= 1")
        return self


class NormalizationConfig(BaseModel):
    max_chars: int = 4000
    max_tokens: int = 1000
    over_limit_policy: Literal["truncate", "block"] = "truncate"
    decode_base64: bool = True
    max_decode_depth: int = 2


class FieldPolicyConfig(BaseModel):
    llm: Literal["mask", "drop", "allow"] = "mask"
    store: Literal["plain", "encrypt", "hash", "none"] = "encrypt"
    min_score: float = 0.5


class PIIConfig(BaseModel):
    enabled: bool = True
    ner_backend: Literal["heuristic", "none"] = "heuristic"
    default_policy: FieldPolicyConfig = FieldPolicyConfig()
    fields: dict[str, FieldPolicyConfig] = Field(default_factory=dict)


class CheckConfig(BaseModel):
    enabled: bool = True
    shadow: bool = False  # log-only: computed, recorded, never enforced
    timeout_ms: int = 50
    on_error: OnError = OnError.ALLOW
    weight: float = 1.0
    params: dict[str, Any] = Field(default_factory=dict)


class CircuitBreakerConfig(BaseModel):
    failure_threshold: int = 5
    cooldown_s: float = 30.0


class UntrustedConfig(BaseModel):
    """Indirect injection: web results, vendor replies, DB rows fed to the planner."""

    flag: float = 0.35
    block: float = 0.65
    checks: list[str] = Field(default_factory=lambda: ["hidden_content", "rules", "classifier"])


class ActionPolicy(BaseModel):
    """Policy for one TaskTree step type (BOOK_SERVICE, SEND_NOTIFICATION, ...)."""

    allowed: bool = True
    requires_confirmation: bool = False  # enforced on BOOK_SERVICE steps
    max_per_hour: int | None = None
    max_per_day: int | None = None


class OutputConfig(BaseModel):
    leak_shingle_size: int = 6
    leak_max_shingle_ratio: float = 0.15
    leak_max_run_words: int = 12
    foreign_pii: Literal["redact", "block"] = "redact"
    foreign_pii_block_count: int = 3  # this many foreign PII values => treat as a data dump
    actions: dict[str, ActionPolicy] = Field(default_factory=dict)


class GuardConfig(BaseModel):
    version: str = "0"
    rules_path: str = "patterns.yaml"
    thresholds: Thresholds = Thresholds()
    normalization: NormalizationConfig = NormalizationConfig()
    pii: PIIConfig = PIIConfig()
    checks: dict[str, CheckConfig] = Field(default_factory=dict)
    circuit_breaker: CircuitBreakerConfig = CircuitBreakerConfig()
    latency_budget_ms: int = 300
    cache_ttl_s: int = 300
    cache_size: int = 10_000
    history_turns: int = 5
    flag_action: Literal["allow", "hold"] = "allow"
    untrusted: UntrustedConfig = UntrustedConfig()
    output: OutputConfig = OutputConfig()
    messages: dict[str, str | None] = Field(default_factory=dict)
    tenants: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # filled in by the loader
    resolved_version: str = ""
    base_dir: str = ""

    def check(self, name: str) -> CheckConfig:
        return self.checks.get(name, CheckConfig())

    def for_tenant(self, tenant_id: str) -> "GuardConfig":
        override = self.tenants.get(tenant_id)
        if not override:
            return self
        merged = deep_merge(self.model_dump(exclude={"tenants"}), override)
        cfg = GuardConfig.model_validate(merged)
        cfg.resolved_version = f"{self.resolved_version}/tenant:{tenant_id}"
        return cfg


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_config(path: str | os.PathLike | None = None,
                overrides: dict[str, Any] | None = None) -> GuardConfig:
    p = Path(path) if path else DEFAULT_CONFIG_PATH
    raw_text = p.read_text(encoding="utf-8")
    data = yaml.safe_load(raw_text) or {}
    if overrides:
        data = deep_merge(data, overrides)
    cfg = GuardConfig.model_validate(data)
    rules_file = (p.parent / cfg.rules_path)
    rules_text = rules_file.read_text(encoding="utf-8") if rules_file.exists() else ""
    digest = hashlib.sha256((raw_text + rules_text + repr(overrides)).encode()).hexdigest()[:10]
    cfg.resolved_version = f"{cfg.version}+{digest}"
    cfg.base_dir = str(p.parent)
    return cfg


class ConfigStore:
    """Hot-reloads the config when the file (or its rules file) changes on disk.

    A failed reload keeps serving the last good config, so a typo in YAML can't take
    the guard down."""

    def __init__(self, path: str | os.PathLike | None = None, check_interval_s: float = 5.0,
                 overrides: dict[str, Any] | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_CONFIG_PATH
        self.check_interval_s = check_interval_s
        self.overrides = overrides
        self._lock = threading.Lock()
        self._cfg = load_config(self.path, overrides)
        self._mtime = self._current_mtime()
        self._last_check = time.monotonic()
        self.last_error: str | None = None
        self.listeners: list = []  # callables(cfg) notified after a successful reload

    @classmethod
    def from_config(cls, cfg: GuardConfig) -> "ConfigStore":
        store = cls.__new__(cls)
        store.path, store.check_interval_s, store.overrides = None, float("inf"), None
        store._lock, store._cfg, store._mtime = threading.Lock(), cfg, 0.0
        store._last_check, store.last_error, store.listeners = time.monotonic(), None, []
        return store

    def _current_mtime(self) -> float:
        if self.path is None:
            return 0.0
        files = [self.path, self.path.parent / self._cfg.rules_path]
        return max((f.stat().st_mtime for f in files if f.exists()), default=0.0)

    def get(self, tenant_id: str = "default") -> GuardConfig:
        now = time.monotonic()
        if self.path is not None and now - self._last_check >= self.check_interval_s:
            self._last_check = now
            self.maybe_reload()
        return self._cfg.for_tenant(tenant_id)

    def maybe_reload(self) -> bool:
        mtime = self._current_mtime()
        if mtime == self._mtime:
            return False
        with self._lock:
            try:
                new = load_config(self.path, self.overrides)
            except Exception as e:  # keep last good config
                self.last_error = f"{type(e).__name__}: {e}"
                return False
            self._cfg, self._mtime, self.last_error = new, mtime, None
        for fn in self.listeners:
            fn(new)
        return True

    @property
    def config(self) -> GuardConfig:
        return self._cfg

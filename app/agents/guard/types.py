"""Core data types shared across the guard (section 8: Check -> CheckResult)."""
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from .config import GuardConfig
    from .normalize import NormalizedText
    from .pii.detectors import PIISpan
    from .pii.vault import PIIVault


class Verdict(str, enum.Enum):
    ALLOW = "allow"
    ALLOW_WITH_REDACTION = "allow_with_redaction"
    FLAG_FOR_REVIEW = "flag_for_review"
    BLOCK = "block"
    ESCALATE = "escalate"  # e.g. self-harm -> helpline route (section 3 hooks in here)


VERDICT_SEVERITY = {
    Verdict.ALLOW: 0,
    Verdict.ALLOW_WITH_REDACTION: 1,
    Verdict.FLAG_FOR_REVIEW: 2,
    Verdict.ESCALATE: 3,
    Verdict.BLOCK: 4,
}


class Source(str, enum.Enum):
    """Where a piece of text came from. Anything other than USER is 'indirect'."""

    USER = "user"
    WEB = "web"
    VENDOR = "vendor"
    DB = "db"
    TOOL = "tool"


class OnError(str, enum.Enum):
    """Fail-open vs fail-closed per check (section 8)."""

    ALLOW = "allow"  # fail open: ignore the failed check
    FLAG = "flag"  # degrade: at least flag for review
    BLOCK = "block"  # fail closed


@dataclass
class CheckResult:
    check: str
    score: float = 0.0  # 0 = clean, 1 = certainly malicious
    category: str = "none"
    reason: str = ""  # internal only, never shown to end users
    rule_ids: list[str] = field(default_factory=list)
    hard_block: bool = False
    error: str | None = None
    on_error: OnError = OnError.ALLOW
    latency_ms: float = 0.0
    shadow: bool = False
    skipped: bool = False
    weight: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_log(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "score": round(self.score, 4),
            "category": self.category,
            "rule_ids": self.rule_ids,
            "hard_block": self.hard_block,
            "error": self.error,
            "latency_ms": round(self.latency_ms, 2),
            "shadow": self.shadow,
            "skipped": self.skipped,
        }


@dataclass
class GuardRequest:
    text: str
    user_id: str = "anonymous"
    session_id: str | None = None
    tenant_id: str = "default"
    source: Source = Source.USER
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    ip: str | None = None


@dataclass
class GuardContext:
    """Everything a Check may look at. Checks must treat it as read-only."""

    request: GuardRequest
    normalized: "NormalizedText"
    config: "GuardConfig"
    history: list[str] = field(default_factory=list)  # previous normalized user turns
    prior_flags: int = 0  # how many recent turns in this session were flagged/blocked
    pii_spans: list["PIISpan"] = field(default_factory=list)
    partial_risk: float = 0.0  # risk from cheaper tiers, available to expensive tiers


@dataclass
class GuardDecision:
    request_id: str
    verdict: Verdict
    risk_score: float
    safe_text: str | None  # what may be sent to the LLM (PII masked); None when blocked
    user_message: str | None  # friendly, non-revealing message for block/flag
    results: list[CheckResult]
    rule_ids: list[str]
    categories: list[str]
    latency_ms: float
    config_version: str
    truncated: bool = False
    cached: bool = False
    vault: "PIIVault | None" = None
    pii_types: list[str] = field(default_factory=list)
    redacted_for_log: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict in (Verdict.ALLOW, Verdict.ALLOW_WITH_REDACTION, Verdict.FLAG_FOR_REVIEW)

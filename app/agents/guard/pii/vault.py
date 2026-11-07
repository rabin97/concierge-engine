"""Section 4: reversible masking and per-field policies.

The LLM only ever sees tokens like ``<PHONE_1>``. The vault lives inside our system,
so the service that actually books the plumber can call ``vault.unmask_obj(args)``
and get the real phone number back.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from .detectors import PIISpan, digits

TOKEN_RE = re.compile(r"<\s*([A-Z][A-Z_]*?_\d+)\s*>")
_NUMERIC_TYPES = {"PHONE", "AADHAAR", "CREDIT_CARD", "PIN_CODE"}

LLMAction = Literal["mask", "drop", "allow"]
StoreAction = Literal["plain", "encrypt", "hash", "none"]


@dataclass
class FieldPolicy:
    """Clear rule per field: what the LLM sees, what we store, what we log."""

    llm: LLMAction = "mask"
    store: StoreAction = "encrypt"
    min_score: float = 0.5
    # logs are always redacted; there is deliberately no option to log raw values


def canonical(entity_type: str, value: str) -> str:
    if entity_type in _NUMERIC_TYPES:
        d = digits(value)
        return d[-10:] if entity_type == "PHONE" else d
    return re.sub(r"\s+", " ", value.strip().lower())


class PIIVault:
    """Per-request (or per-session) token <-> value map. Same value => same token."""

    def __init__(self) -> None:
        self._by_token: dict[str, tuple[str, str]] = {}  # token -> (type, original value)
        self._by_value: dict[tuple[str, str], str] = {}
        self._counters: Counter[str] = Counter()

    def tokenize(self, entity_type: str, value: str) -> str:
        key = (entity_type, canonical(entity_type, value))
        if key in self._by_value:
            return self._by_value[key]
        self._counters[entity_type] += 1
        token = f"<{entity_type}_{self._counters[entity_type]}>"
        self._by_value[key] = token
        self._by_token[token] = (entity_type, value)
        return token

    def resolve(self, token: str) -> str | None:
        m = TOKEN_RE.fullmatch(token.strip())
        if not m:
            return None
        hit = self._by_token.get(f"<{m.group(1)}>")
        return hit[1] if hit else None

    def unmask(self, text: str) -> str:
        def sub(m: re.Match) -> str:
            hit = self._by_token.get(f"<{m.group(1)}>")
            return hit[1] if hit else m.group(0)
        return TOKEN_RE.sub(sub, text)

    def unmask_obj(self, obj: Any) -> Any:
        """Recursively unmask tool-call arguments (dicts/lists/strings)."""
        if isinstance(obj, str):
            return self.unmask(obj)
        if isinstance(obj, dict):
            return {k: self.unmask_obj(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return type(obj)(self.unmask_obj(v) for v in obj)
        return obj

    def contains_value(self, entity_type: str, value: str) -> bool:
        return (entity_type, canonical(entity_type, value)) in self._by_value

    def tokens(self) -> list[str]:
        return list(self._by_token)

    def __len__(self) -> int:
        return len(self._by_token)


@dataclass
class MaskResult:
    masked_text: str  # for the LLM
    log_text: str  # irreversibly redacted, safe for logs
    spans: list[PIISpan] = field(default_factory=list)
    types: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.spans)


def apply_policies(text: str, spans: list[PIISpan], policies: dict[str, FieldPolicy],
                   vault: PIIVault, default: FieldPolicy | None = None) -> MaskResult:
    default = default or FieldPolicy()
    llm_out, log_out = text, text
    acted: list[PIISpan] = []
    for s in sorted(spans, key=lambda s: s.start, reverse=True):
        pol = policies.get(s.entity_type, default)
        log_out = log_out[: s.start] + f"[{s.entity_type}]" + log_out[s.end:]
        if pol.llm == "allow":
            continue
        repl = vault.tokenize(s.entity_type, s.text) if pol.llm == "mask" else f"[{s.entity_type}_REMOVED]"
        llm_out = llm_out[: s.start] + repl + llm_out[s.end:]
        acted.append(s)
    return MaskResult(llm_out, log_out, sorted(acted, key=lambda s: s.start),
                      sorted({s.entity_type for s in acted}))


# --------------------------------------------------------------------------- storage
class Encryptor(Protocol):
    """Back this with KMS (or any envelope-encryption service) in production."""

    def encrypt(self, data: bytes) -> bytes: ...
    def decrypt(self, data: bytes) -> bytes: ...


def hmac_hash(value: str, key: bytes) -> str:
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


def storage_value(span: PIISpan, policy: FieldPolicy, hmac_key: bytes,
                  encryptor: Encryptor | None = None) -> str | None:
    """What may be persisted for this field, according to its policy."""
    if policy.store == "none":
        return None
    if policy.store == "hash":
        return hmac_hash(canonical(span.entity_type, span.text), hmac_key)
    if policy.store == "encrypt":
        if encryptor is None:
            raise RuntimeError(f"{span.entity_type} requires encryption but no encryptor configured")
        return encryptor.encrypt(span.text.encode()).decode()
    return span.text

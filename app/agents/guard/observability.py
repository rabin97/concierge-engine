"""Section 10: structured decision logs, metrics, audit trail, review queue.

Nothing here ever receives raw PII: decisions carry ``redacted_for_log`` (every PII
span replaced by its type) and user IDs are HMAC-hashed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
import uuid
import warnings
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable

if TYPE_CHECKING:  # pragma: no cover
    from .types import GuardDecision, GuardRequest

_DEV_KEY = b"guard-dev-key-change-me"


def hmac_key() -> bytes:
    key = os.environ.get("GUARD_HMAC_KEY")
    if not key:
        warnings.warn("GUARD_HMAC_KEY not set; using a development key", stacklevel=2)
        return _DEV_KEY
    return key.encode()


def hash_id(value: str | None, key: bytes) -> str | None:
    if value is None:
        return None
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:24]


# --------------------------------------------------------------------------- logging
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = getattr(record, "payload", None)
        base = {"ts": datetime.now(timezone.utc).isoformat(), "level": record.levelname,
                "logger": record.name}
        if isinstance(payload, dict):
            base.update(payload)
        else:
            base["msg"] = record.getMessage()
        return json.dumps(base, ensure_ascii=False, default=str)


def configure_json_logging(level: int = logging.INFO) -> None:
    h = logging.StreamHandler()
    h.setFormatter(JsonFormatter())
    root = logging.getLogger("app.agents.guard")
    root.handlers[:] = [h]
    root.setLevel(level)
    root.propagate = False


def decision_record(decision: "GuardDecision", request: "GuardRequest", key: bytes) -> dict[str, Any]:
    return {
        "event": "guard_decision",
        "request_id": decision.request_id,
        "user": hash_id(request.user_id, key),
        "session": hash_id(request.session_id, key),
        "ip": hash_id(request.ip, key),
        "tenant": request.tenant_id,
        "source": request.source.value,
        "verdict": decision.verdict.value,
        "risk": round(decision.risk_score, 4),
        "rule_ids": decision.rule_ids,
        "categories": decision.categories,
        "checks": [r.to_log() for r in decision.results],
        "pii_types": decision.pii_types,
        "latency_ms": round(decision.latency_ms, 2),
        "config_version": decision.config_version,
        "truncated": decision.truncated,
        "cached": decision.cached,
        "prompt_redacted": decision.redacted_for_log,  # never the raw prompt
    }


class DecisionLogger:
    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger("app.agents.guard.decisions")

    def log(self, record: dict[str, Any]) -> None:
        lvl = logging.WARNING if record.get("verdict") in ("block", "escalate") else logging.INFO
        self.logger.log(lvl, record.get("event", "event"), extra={"payload": record})


# --------------------------------------------------------------------------- metrics
class Metrics:
    """Tiny in-process registry. Swap for prometheus_client/OpenTelemetry in prod;
    ``render_prometheus`` already emits the text exposition format."""

    def __init__(self, window: int = 10_000) -> None:
        self._lock = threading.Lock()
        self.counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self.samples: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=window))

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        with self._lock:
            self.counters[(name, tuple(sorted(labels.items())))] += value

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            self.samples[name].append(value)

    def counter(self, name: str, **labels: str) -> float:
        """Sum of all series of ``name`` whose labels include ``labels``."""
        want = set(labels.items())
        return sum(v for (n, lab), v in self.counters.items() if n == name and want <= set(lab))

    def total(self, name: str) -> float:
        return sum(v for (n, _), v in self.counters.items() if n == name)

    def percentile(self, name: str, q: float) -> float | None:
        data = sorted(self.samples.get(name, ()))
        if not data:
            return None
        k = (len(data) - 1) * q
        lo, hi = int(k), min(int(k) + 1, len(data) - 1)
        return data[lo] + (data[hi] - data[lo]) * (k - lo)

    def snapshot(self) -> dict[str, Any]:
        decisions = self.total("guard_decisions_total")
        blocked = self.counter("guard_decisions_total", verdict="block")
        appeals = self.total("guard_appeals_total")
        overturned = self.total("guard_false_positives_total")
        return {
            "decisions": decisions,
            "block_rate": blocked / decisions if decisions else 0.0,
            "flag_rate": self.counter("guard_decisions_total", verdict="flag_for_review") / decisions if decisions else 0.0,
            "appeals": appeals,
            # confirmed false positives among blocks (from appeals + review labels)
            "false_positive_rate": overturned / blocked if blocked else 0.0,
            "latency_p50_ms": self.percentile("guard_latency_ms", 0.5),
            "latency_p95_ms": self.percentile("guard_latency_ms", 0.95),
            "rule_hits": {dict(lab).get("rule"): v for (n, lab), v in self.counters.items()
                          if n == "guard_rule_hits_total"},
        }

    def render_prometheus(self) -> str:
        lines = []
        for (name, labels), v in sorted(self.counters.items()):
            lab = ",".join(f'{k}="{val}"' for k, val in labels)
            lines.append(f"{name}{{{lab}}} {v}" if lab else f"{name} {v}")
        for name in self.samples:
            for q in (0.5, 0.95, 0.99):
                lines.append(f'{name}{{quantile="{q}"}} {self.percentile(name, q)}')
        return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- audit
class AuditTrail:
    """Append-only JSONL with a hash chain, so edits or deletions are detectable.

    For DPDP Act 2023: records hold no raw PII (hashed user IDs, redacted prompt), and
    ``purge`` enforces the retention period, leaving a signed anchor record behind."""

    GENESIS = "0" * 64

    def __init__(self, path: str | os.PathLike, retention_days: int = 180) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.retention_days = retention_days
        self._lock = threading.Lock()
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return self.GENESIS
        last = self.GENESIS
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    @staticmethod
    def _digest(prev: str, body: dict[str, Any]) -> str:
        blob = json.dumps(body, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256((prev + blob).encode()).hexdigest()

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            body = {"ts": datetime.now(timezone.utc).isoformat(), **record}
            h = self._digest(self._last_hash, body)
            entry = {"body": body, "prev": self._last_hash, "hash": h}
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
            self._last_hash = h
            return entry

    def entries(self) -> Iterable[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def verify(self) -> tuple[bool, int | None]:
        """Returns (ok, index_of_first_bad_entry)."""
        prev = None
        for i, e in enumerate(self.entries()):
            if prev is not None and e["prev"] != prev:
                return False, i
            if self._digest(e["prev"], e["body"]) != e["hash"]:
                return False, i
            prev = e["hash"]
        return True, None

    def purge(self, now: datetime | None = None) -> int:
        now = now or datetime.now(timezone.utc)
        cutoff = now - timedelta(days=self.retention_days)
        with self._lock:
            entries = list(self.entries())
            keep = [e for e in entries if datetime.fromisoformat(e["body"]["ts"]) >= cutoff]
            removed = len(entries) - len(keep)
            if not removed:
                return 0
            anchor_prev = entries[len(entries) - len(keep) - 1]["hash"]
            anchor_body = {"ts": now.isoformat(), "event": "retention_purge", "removed": removed,
                           "last_removed_hash": anchor_prev, "retention_days": self.retention_days}
            out, prev = [], self.GENESIS
            for body in [anchor_body] + [e["body"] for e in keep]:
                h = self._digest(prev, body)
                out.append({"body": body, "prev": prev, "hash": h})
                prev = h
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in out), encoding="utf-8")
            tmp.replace(self.path)
            self._last_hash = prev
            return removed


# --------------------------------------------------------------------------- review queue
class ReviewQueue:
    """Flagged prompts and appeals for human review. Labels flow back into the eval
    datasets (``export_labeled``) and from there into rules and classifier training."""

    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.items: dict[str, dict[str, Any]] = {}
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    it = json.loads(line)
                    self.items[it["id"]] = {**self.items.get(it["id"], {}), **it}

    def _write(self, item: dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")

    def enqueue(self, *, request_id: str, text_redacted: str, verdict: str, risk: float,
                rule_ids: list[str], reason: str = "flagged", config_version: str = "") -> str:
        item = {"id": uuid.uuid4().hex[:12], "request_id": request_id, "text": text_redacted,
                "verdict": verdict, "risk": risk, "rule_ids": rule_ids, "reason": reason,
                "config_version": config_version, "status": "pending", "created": time.time()}
        with self._lock:
            self.items[item["id"]] = item
            self._write(item)
        return item["id"]

    def pending(self) -> list[dict[str, Any]]:
        return [i for i in self.items.values() if i["status"] == "pending"]

    def label(self, item_id: str, label: str, reviewer: str) -> dict[str, Any]:
        if label not in ("attack", "benign"):
            raise ValueError("label must be 'attack' or 'benign'")
        with self._lock:
            item = self.items[item_id]
            item.update(status="labeled", label=label, reviewer=reviewer, labeled_at=time.time())
            self._write({"id": item_id, "status": "labeled", "label": label,
                         "reviewer": reviewer, "labeled_at": item["labeled_at"]})
        return item

    def export_labeled(self, path: str | os.PathLike) -> int:
        rows = [{"text": i["text"], "label": i["label"], "source": "review_queue",
                 "request_id": i["request_id"]} for i in self.items.values() if i.get("status") == "labeled"]
        Path(path).write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
        return len(rows)

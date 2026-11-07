"""Section 2, layer 1: cheap rules. Plus hidden-content and multi-turn checks."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..normalize import NormalizationSettings, normalize
from ..types import GuardContext
from .base import TIER_RULES, Check, noisy_or

DEFAULT_VARIANTS = ("lower", "skeleton", "decoded", "leet", "despaced", "payloads", "payloads_leet")
_OBFUSCATED_VARIANTS = {"skeleton", "decoded", "leet", "despaced", "payloads", "payloads_leet", "compact"}


@dataclass
class Rule:
    id: str
    category: str
    severity: float
    patterns: list[re.Pattern]
    variants: tuple[str, ...] = DEFAULT_VARIANTS
    action: str = "score"  # score | block
    status: str = "active"  # active | shadow | disabled
    description: str = ""


@dataclass
class RuleHit:
    rule: Rule
    variants: set[str] = field(default_factory=set)

    @property
    def obfuscated_only(self) -> bool:
        return "lower" not in self.variants and bool(self.variants & _OBFUSCATED_VARIANTS)


class RuleEngine:
    def __init__(self, rules: list[Rule], version: str = "0") -> None:
        self.rules = rules
        self.version = version

    @classmethod
    def from_yaml(cls, path: str | Path) -> "RuleEngine":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        rules = []
        seen = set()
        for r in data.get("rules", []):
            if r["id"] in seen:
                raise ValueError(f"duplicate rule id {r['id']}")
            seen.add(r["id"])
            if r.get("status", "active") == "disabled":
                continue
            rules.append(Rule(
                id=r["id"],
                category=r.get("category", "injection"),
                severity=float(r.get("severity", 0.5)),
                patterns=[re.compile(p, re.I | re.S) for p in r["patterns"]],
                variants=tuple(r.get("variants", DEFAULT_VARIANTS)),
                action=r.get("action", "score"),
                status=r.get("status", "active"),
                description=r.get("description", ""),
            ))
        return cls(rules, str(data.get("version", "0")))

    def match(self, variants: dict[str, str]) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for rule in self.rules:
            hit = None
            for vname in rule.variants:
                text = variants.get(vname)
                if not text:
                    continue
                if any(p.search(text) for p in rule.patterns):
                    hit = hit or RuleHit(rule)
                    hit.variants.add(vname)
            if hit:
                hits.append(hit)
        return hits


def score_hits(hits: list[RuleHit], obfuscation_bonus: float = 0.1) -> tuple[float, bool, list[RuleHit]]:
    active = [h for h in hits if h.rule.status == "active"]
    scores = [min(1.0, h.rule.severity + (obfuscation_bonus if h.obfuscated_only else 0.0)) for h in active]
    hard = any(h.rule.action == "block" for h in active)
    return noisy_or(scores), hard, active


class RuleCheck(Check):
    name = "rules"
    tier = TIER_RULES
    category = "injection"

    def __init__(self, engine: RuleEngine) -> None:
        self.engine = engine

    async def run(self, ctx: GuardContext):
        hits = self.engine.match(ctx.normalized.variants)
        score, hard, active = score_hits(hits)
        shadow_ids = [h.rule.id for h in hits if h.rule.status == "shadow"]
        if not active:
            return self.result(0.0, metadata={"shadow_rule_ids": shadow_ids,
                                              "rules_version": self.engine.version})
        top = max(active, key=lambda h: h.rule.severity)
        return self.result(
            score,
            category=top.rule.category,
            reason=f"matched {len(active)} rule(s)",
            rule_ids=[h.rule.id for h in active],
            hard_block=hard,
            metadata={"variants": {h.rule.id: sorted(h.variants) for h in active},
                      "shadow_rule_ids": shadow_ids, "rules_version": self.engine.version},
        )


class HiddenContentCheck(Check):
    """Invisible characters, bidi overrides, tag smuggling and mixed-script words are
    rarely innocent in a household request."""

    name = "hidden_content"
    tier = TIER_RULES
    category = "obfuscation"

    async def run(self, ctx: GuardContext):
        n = ctx.normalized
        found = [(score, rule_id) for present, score, rule_id in (
            (n.invisible_count, min(0.5, 0.25 + 0.02 * n.invisible_count), "OBF-INVISIBLE"),
            (n.bidi_count, 0.45, "OBF-BIDI"),
            (n.tag_count, 0.65, "OBF-TAG-SMUGGLING"),
            (n.mixed_script_words, min(0.6, 0.35 + 0.1 * (n.mixed_script_words - 1)), "OBF-MIXED-SCRIPT"),
            (n.spaced_letter_runs, 0.5, "OBF-SPACED-LETTERS"),
            (n.decoded_payloads, 0.2, "OBF-ENCODED-PAYLOAD"),
        ) if present]
        signals = [score for score, _ in found]
        ids = [rule_id for _, rule_id in found]
        if not signals:
            return self.result(0.0)
        return self.result(noisy_or(signals), reason="hidden or obfuscated content", rule_ids=ids,
                           metadata={"invisible": n.invisible_count, "bidi": n.bidi_count,
                                     "tags": n.tag_count, "mixed_script": n.mixed_script_words})


class MultiTurnCheck(Check):
    """Attackers split payloads across turns ("ignore all" / "previous instructions").
    Join the recent turns and flag rules that only fire on the joined text."""

    name = "multi_turn"
    tier = TIER_RULES
    category = "multi_turn_injection"
    applies_to_untrusted = False

    def __init__(self, engine: RuleEngine, settings: NormalizationSettings | None = None,
                 discount: float = 0.9) -> None:
        self.engine = engine
        self.settings = settings or NormalizationSettings(max_chars=20_000, max_tokens=5_000)
        self.discount = discount

    async def run(self, ctx: GuardContext):
        escalation = min(0.3, 0.1 * ctx.prior_flags)
        if not ctx.history:
            return self.result(escalation, rule_ids=["MT-ESCALATION"] if escalation else [])
        current_ids = {h.rule.id for h in self.engine.match(ctx.normalized.variants)}
        seen_ids: set[str] = set(current_ids)
        for turn in ctx.history:
            seen_ids |= {h.rule.id for h in self.engine.match(normalize(turn, self.settings).variants)}
        joined = normalize(" ".join([*ctx.history, ctx.normalized.clean]), self.settings)
        new_hits = [h for h in self.engine.match(joined.variants) if h.rule.id not in seen_ids]
        score, _, active = score_hits(new_hits)
        score = noisy_or([score * self.discount, escalation])
        ids = [f"MT:{h.rule.id}" for h in active] + (["MT-ESCALATION"] if escalation else [])
        if score <= 0:
            return self.result(0.0)
        return self.result(score, reason="payload split across turns" if active else "repeat offender",
                           rule_ids=ids)

"""Section 2, layer 2: classifier that returns a score, not just yes/no.

``HeuristicClassifier`` is a dependency-free logistic model with hand-set weights.
Anything that implements ``InjectionClassifier`` can replace it; paraphrased attacks it
misses are left to the LLM judge (layer 3).
"""
from __future__ import annotations

import asyncio
import math
import re
from typing import Protocol

from ..types import GuardContext
from .base import TIER_MODEL, Check


class InjectionClassifier(Protocol):
    name: str

    async def score(self, text: str) -> float:
        """Probability (0..1) that ``text`` is an injection / jailbreak."""
        ...


# --------------------------------------------------------------------------- heuristic
_OVERRIDE = re.compile(r"\b(ignore|disregard|forget|override|bypass|pretend|reveal|jailbreak|"
                       r"unrestricted|uncensored|obey|comply|roleplay|simulate|persona)\b")
_META = re.compile(r"\b(instructions?|prompts?|system|rules|guidelines|policy|policies|mode|"
                   r"assistant|ai|model|restrictions|filters|guardrails|developer|programming|"
                   r"directives?|context|llm|chatbot|persona)\b")
_ADDRESS_MODEL = re.compile(r"\b(you are|you're|you must|you will|your (instructions|rules|task|"
                            r"prompt|creators?|programming))\b")
_HOUSEHOLD = re.compile(
    r"\b(plumb\w*|electric\w*|clean\w*|maid|cook|chef|laundry|grocer\w*|repair\w*|fix|leak\w*|"
    r"ac|fridge|washing|geyser|tap|pipe|wiring|carpent\w*|paint\w*|pest|deliver\w*|book\w*|"
    r"appointment|slot|tomorrow|today|morning|evening|service|technician|bathroom|kitchen|"
    r"water|tank|sofa|furniture|garden\w*|driver|nanny|babysit\w*|bill|rent|gas|cylinder|"
    r"ghar|kal|aaj|safai|kaam|mistri|bijli|paani|nal|chahiye|bhejo)\b")
_SPECIAL = re.compile(r"[<>\[\]{}|#`]")


class HeuristicClassifier:
    """Logistic model over hand-built features. Deterministic, ~0.1 ms."""

    name = "heuristic-v1"

    def __init__(self, bias: float = -2.6) -> None:
        self.bias = bias

    def features(self, text: str) -> dict[str, float]:
        t = text.lower()
        words = max(1, len(t.split()))
        return {
            "override": len(_OVERRIDE.findall(t)),
            "meta": len(_META.findall(t)),
            "address_model": len(_ADDRESS_MODEL.findall(t)),
            "household": len(_HOUSEHOLD.findall(t)),
            "special_ratio": len(_SPECIAL.findall(text)) / max(1, len(text)) * 100,
            "upper_ratio": sum(c.isupper() for c in text) / max(1, sum(c.isalpha() for c in text)),
            "long": 1.0 if words > 150 else 0.0,
        }

    def _logit(self, f: dict[str, float]) -> float:
        return (self.bias
                + 1.6 * min(f["override"], 3)
                + 0.9 * min(f["meta"], 4)
                + 0.8 * min(f["address_model"], 3)
                - 0.9 * min(f["household"], 4)
                + 0.15 * min(f["special_ratio"], 10)
                + 1.0 * (f["upper_ratio"] > 0.6)
                + 0.5 * f["long"])

    async def score(self, text: str) -> float:
        return 1.0 / (1.0 + math.exp(-self._logit(self.features(text))))


# --------------------------------------------------------------------------- check
class ClassifierCheck(Check):
    name = "classifier"
    tier = TIER_MODEL
    category = "injection_model"

    def __init__(self, classifier: InjectionClassifier) -> None:
        self.classifier = classifier

    async def run(self, ctx: GuardContext):
        n = ctx.normalized
        # score the readable text and any decoded payloads; take the worst
        texts = [n.variants.get("despaced") or n.clean, *n.decoded_payloads]
        scores = await asyncio.gather(*(self.classifier.score(t) for t in texts if t))
        s = max(scores, default=0.0)
        return self.result(s, reason=f"{self.classifier.name} score",
                           metadata={"model": self.classifier.name, "raw_score": round(s, 4)})

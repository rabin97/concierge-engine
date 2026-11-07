"""Section 8: pluggable checks. Each check returns a CheckResult with score,
category and reason. Tier decides order: 0 = rules (cheap), 1 = models, 2 = LLM judge."""
from __future__ import annotations

import abc

from ..types import CheckResult, GuardContext

TIER_RULES = 0
TIER_MODEL = 1
TIER_JUDGE = 2


class Check(abc.ABC):
    name: str = "check"
    tier: int = TIER_RULES
    category: str = "none"
    #: True for checks that only make sense on borderline inputs (the LLM judge)
    borderline_only: bool = False
    #: run on indirect content (web/vendor/DB text) as well as user text
    applies_to_untrusted: bool = True

    @abc.abstractmethod
    async def run(self, ctx: GuardContext) -> CheckResult:
        ...

    def result(self, score: float = 0.0, **kw) -> CheckResult:
        kw.setdefault("category", self.category if score > 0 else "none")
        return CheckResult(check=self.name, score=max(0.0, min(1.0, score)), **kw)


def noisy_or(scores: list[float]) -> float:
    """Combine independent signals: 1 - prod(1 - s). Two 0.5s give 0.75, not 1.0."""
    p = 1.0
    for s in scores:
        p *= 1.0 - max(0.0, min(1.0, s))
    return 1.0 - p

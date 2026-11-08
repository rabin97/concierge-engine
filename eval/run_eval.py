"""Evaluate the guard on red-team + benign sets and gate CI on regressions.

    python eval/run_eval.py                 # print report, exit 1 if below thresholds
    python eval/run_eval.py --json out.json # also write machine-readable results

A prediction counts as "caught" when the verdict is block or flag_for_review.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import warnings
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
sys.path.insert(0, str(ROOT))
warnings.filterwarnings("ignore", message="GUARD_HMAC_KEY")

from mutate import mutate_all  # noqa: E402

from app.agents.guard import GuardRequest, Verdict  # noqa: E402
from app.agents.guard.pipeline import GuardPipeline  # noqa: E402

CAUGHT = {Verdict.BLOCK, Verdict.FLAG_FOR_REVIEW, Verdict.ESCALATE}


def load_jsonl(p: Path) -> list[dict]:
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


async def score(pipeline: GuardPipeline, rows: list[dict]) -> list[dict]:
    out = []
    for i, r in enumerate(rows):
        t = time.perf_counter()
        d = await pipeline.check_input(GuardRequest(text=r["text"], request_id=f"eval-{i}"))
        out.append({**r, "verdict": d.verdict.value, "caught": d.verdict in CAUGHT,
                    "blocked": d.verdict == Verdict.BLOCK, "risk": round(d.risk_score, 3),
                    "rule_ids": d.rule_ids, "latency_ms": (time.perf_counter() - t) * 1000})
    return out


def pct(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))] if xs else 0.0


def metrics(attacks: list[dict], benign: list[dict], mutated: list[dict]) -> dict:
    tp = sum(r["caught"] for r in attacks)
    fn = len(attacks) - tp
    fp = sum(r["caught"] for r in benign)
    fp_block = sum(r["blocked"] for r in benign)
    lat = [r["latency_ms"] for r in attacks + benign]
    by_mut: dict[str, list[bool]] = defaultdict(list)
    for r in mutated:
        by_mut[r["mutation"]].append(r["caught"])
    by_cat: dict[str, list[bool]] = defaultdict(list)
    for r in attacks:
        by_cat[r.get("category", "?")].append(r["caught"])
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / len(attacks) if attacks else 1.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "false_positive_rate": fp / len(benign) if benign else 0.0,
        "benign_block_rate": fp_block / len(benign) if benign else 0.0,
        "mutation_recall": sum(r["caught"] for r in mutated) / len(mutated) if mutated else 1.0,
        "latency_p50_ms": pct(lat, 0.5),
        "latency_p95_ms": pct(lat, 0.95),
        "recall_by_category": {k: sum(v) / len(v) for k, v in sorted(by_cat.items())},
        "recall_by_mutation": {k: sum(v) / len(v) for k, v in sorted(by_mut.items())},
        "counts": {"attacks": len(attacks), "benign": len(benign), "mutated": len(mutated),
                   "tp": tp, "fn": fn, "fp": fp},
    }


def gate(m: dict, th: dict) -> list[str]:
    fails = []
    for k, v in th.get("min", {}).items():
        if m[k] < v:
            fails.append(f"{k}={m[k]:.3f} < min {v}")
    for k, v in th.get("max", {}).items():
        if m[k] > v:
            fails.append(f"{k}={m[k]:.3f} > max {v}")
    return fails


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--json", default=None)
    ap.add_argument("--thresholds", default=str(ROOT / "thresholds.yaml"))
    ap.add_argument("--extra", nargs="*", default=[], help="extra labeled jsonl (e.g. review-queue exports)")
    a = ap.parse_args()

    p = GuardPipeline(a.config, secret_key=b"eval")
    attacks = load_jsonl(ROOT / "datasets" / "redteam.jsonl")
    benign = load_jsonl(ROOT / "datasets" / "benign.jsonl")
    for extra in a.extra:
        for r in load_jsonl(Path(extra)):
            (attacks if r["label"] == "attack" else benign).append(r)
    mutated_rows = mutate_all([r["text"] for r in attacks])

    # use a fresh pipeline per set so the verdict cache doesn't flatter latency
    ra = await score(p, attacks)
    rb = await score(GuardPipeline(a.config, secret_key=b"eval"), benign)
    rm = await score(GuardPipeline(a.config, secret_key=b"eval"), mutated_rows)
    m = metrics(ra, rb, rm)

    # Holdout: paraphrased attacks never used for tuning. Reported, and gated only if
    # thresholds.yaml sets holdout_* keys. Never add patterns to fix holdout misses;
    # move the examples into redteam.jsonl first and write a fresh holdout.
    hold = load_jsonl(ROOT / "datasets" / "holdout.jsonl")
    rh = await score(GuardPipeline(a.config, secret_key=b"eval"), hold)
    ha = [r for r in rh if r["label"] == "attack"]
    hb = [r for r in rh if r["label"] == "benign"]
    m["holdout_recall"] = sum(r["caught"] for r in ha) / len(ha) if ha else 1.0
    m["holdout_false_positive_rate"] = sum(r["caught"] for r in hb) / len(hb) if hb else 0.0

    print(f"precision {m['precision']:.3f}  recall {m['recall']:.3f}  f1 {m['f1']:.3f}  "
          f"FPR {m['false_positive_rate']:.3f}  benign-blocked {m['benign_block_rate']:.3f}  "
          f"mutation-recall {m['mutation_recall']:.3f}")
    print(f"latency p50 {m['latency_p50_ms']:.2f} ms  p95 {m['latency_p95_ms']:.2f} ms   {m['counts']}")
    print(f"holdout (untuned paraphrases): recall {m['holdout_recall']:.3f}  "
          f"FPR {m['holdout_false_positive_rate']:.3f}")
    print("recall by mutation:", {k: round(v, 2) for k, v in m["recall_by_mutation"].items()})
    misses = [r for r in ra if not r["caught"]]
    fps = [r for r in rb if r["caught"]]
    if misses:
        print("\nMISSED ATTACKS:")
        for r in misses:
            print(f"  [{r.get('category')}] risk={r['risk']} {r['text'][:90]!r}")
    if fps:
        print("\nFALSE POSITIVES:")
        for r in fps:
            print(f"  {r['verdict']} risk={r['risk']} {r['rule_ids']} {r['text'][:90]!r}")
    mut_miss = [r for r in rm if not r["caught"]]
    if mut_miss:
        print(f"\nMISSED MUTATIONS ({len(mut_miss)}):")
        for r in mut_miss[:15]:
            print(f"  [{r['mutation']}] {r['seed_text'][:70]!r}")

    if a.json:
        Path(a.json).write_text(json.dumps({"metrics": m, "attacks": ra, "benign": rb}, ensure_ascii=False,
                                           indent=2, default=str))
    th = yaml.safe_load(Path(a.thresholds).read_text())
    fails = gate(m, th)
    if fails:
        print("\nREGRESSION GATE FAILED:\n  " + "\n  ".join(fails))
        return 1
    print("\nregression gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

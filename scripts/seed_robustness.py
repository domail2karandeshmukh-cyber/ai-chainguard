"""Supplementary run: do the poisoning results depend on the random seed?

    python -m scripts.seed_robustness            # seeds 0-9 plus the reference seed 42
    python -m scripts.seed_robustness --seeds 0 1 2

The paper's experiments E0, E2, E3 and E4 use one seed (42). The seed decides the split of the digits
into training, fine-tuning and held-out sets, the rows that are poisoned, the initial weights and the
order of the mini-batches. This run repeats the four pipeline variants, unchanged, for other seeds and
records for each: the verification status of the fine-tuned model, whether the gateway deployed it, its
clean accuracy and its backdoor success rate. Writes results/attacks/seed_robustness.json.

Seed 42 is run as well, as a check that the run reproduces the reference results exactly.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

from attacks.common import new_workspace
from attacks.scenario_e_backdoor_poisoning import EPOCHS, TARGET, _quiet
from ml_pipeline.run_pipeline import run_full_pipeline

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "attacks" / "seed_robustness.json"
REFERENCE_SEED = 42
# The same four pipeline variants as attacks/scenario_e_backdoor_poisoning.py (E1 is a storage attack
# on the E0 chain and does not train a model).
VARIANTS = (
    ("E0", "VERIFIED", "clean baseline", {}),
    ("E2", "VERIFIED", "8 % corner trigger before signing, no content checks",
     {"poison_rate": 0.08, "trigger": "corner", "semantic_checks": False}),
    ("E3", "WARNING", "8 % corner trigger before signing, content checks on",
     {"poison_rate": 0.08, "trigger": "corner", "semantic_checks": True}),
    ("E4", "VERIFIED", "5 % left-bar trigger before signing, content checks on",
     {"poison_rate": 0.05, "trigger": "left_bar", "semantic_checks": True}),
)


def run_one(variant: str, expected: str, kw: dict, seed: int) -> dict:
    cg = new_workspace()
    run = run_full_pipeline(cg, epochs=EPOCHS, poison_target=TARGET, log=_quiet, seed=seed, **kw)
    final = run["artifacts"]["final_model"]
    status = str(getattr(cg.verifier.verify(final, context=f"seed:{variant}").status, "value", "?"))
    ev = run["evaluation"]
    return {
        "variant": variant,
        "seed": seed,
        "expected": expected,
        "status": status,
        "as_expected": status == expected,
        "deployed": bool(run["deployment"]["deployed"]),
        "semantic_flags": run["semantic_flags"],
        "poisoned_rows": (run.get("poisoning") or {}).get("poisoned_rows", 0),
        "clean_accuracy": ev["final"]["clean_accuracy"],
        "attack_success_rate": ev["final"]["attack_success_rate"],
        "base_model_attack_success_rate": ev["base"]["attack_success_rate"],
    }


def summarise(rows: list[dict]) -> dict:
    def stats(key: str) -> dict:
        vals = [r[key] for r in rows]
        return {
            "min": round(min(vals), 4),
            "median": round(statistics.median(vals), 4),
            "max": round(max(vals), 4),
            "mean": round(statistics.fmean(vals), 4),
            "stdev": round(statistics.stdev(vals), 4) if len(vals) > 1 else 0.0,
        }

    statuses: dict[str, int] = {}
    for r in rows:
        statuses[r["status"]] = statuses.get(r["status"], 0) + 1
    return {
        "seeds": [r["seed"] for r in rows],
        "runs": len(rows),
        "statuses": statuses,
        "as_expected": sum(r["as_expected"] for r in rows),
        "deployed": sum(r["deployed"] for r in rows),
        "runs_with_content_flags": sum(1 for r in rows if r["semantic_flags"]),
        "clean_accuracy": stats("clean_accuracy"),
        "attack_success_rate": stats("attack_success_rate"),
    }


def main(seeds: list[int]) -> dict:
    started = time.perf_counter()
    all_seeds = [*seeds, REFERENCE_SEED] if REFERENCE_SEED not in seeds else list(seeds)
    rows: list[dict] = []
    for seed in all_seeds:
        for variant, expected, _what, kw in VARIANTS:
            r = run_one(variant, expected, kw, seed)
            rows.append(r)
            print(
                f"seed {seed:>2} {variant}: {r['status']:<8} deployed={str(r['deployed']):<5} "
                f"clean {r['clean_accuracy']:.4f} ASR {r['attack_success_rate']:.4f} flags {r['semantic_flags']}",
                flush=True,
            )
    result = {
        "experiment": "supplementary to E0/E2/E3/E4: the same pipeline variants repeated for other seeds",
        "note": "the seed sets the data split, the poisoned rows, the initial weights and the batch order; "
        "summaries exclude the reference seed, which is listed separately",
        "epochs": EPOCHS,
        "target_label": TARGET,
        "variants": {v: what for v, _e, what, _k in VARIANTS},
        "summary": {
            v: summarise([r for r in rows if r["variant"] == v and r["seed"] != REFERENCE_SEED])
            for v, *_ in VARIANTS
        },
        "reference_seed": {
            "seed": REFERENCE_SEED,
            "rows": [r for r in rows if r["seed"] == REFERENCE_SEED],
        },
        "rows": [r for r in rows if r["seed"] != REFERENCE_SEED],
        "seconds": round(time.perf_counter() - started, 1),
    }
    OUT.write_text(json.dumps(result, indent=1) + "\n")
    print("->", OUT.relative_to(ROOT), f"({result['seconds']} s)")
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seeds", type=int, nargs="+", default=list(range(10)))
    main(ap.parse_args().seeds)

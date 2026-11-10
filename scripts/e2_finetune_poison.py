"""Supplementary run: the backdoor injected into the fine-tuning dataset.

    python -m scripts.e2_finetune_poison

The paper's experiments E2-E4 poison the base model's training set and fine-tune on clean data. The
project brief's example scenario injects the backdoor into the fine-tuning dataset instead. This run
does exactly that, with everything else as in E2 and E3: 8 % of the fine-tuning rows get the 2x2 corner
trigger and the label 7 BEFORE the data steward signs them, once without and once with the content
checks; the base model is trained on clean data; every artifact is attested and the fine-tuned model is
sent to the deployment gateway. Writes results/attacks/e2_finetune_poison.json.
"""

from __future__ import annotations

import json
from pathlib import Path

from attacks.common import new_workspace
from attacks.scenario_e_backdoor_poisoning import EPOCHS, TARGET, _quiet
from ml_pipeline.run_pipeline import run_full_pipeline

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "attacks" / "e2_finetune_poison.json"
VARIANTS = (
    ("FT-E2", False, "VERIFIED", "poison in the fine-tuning set before signing, no content checks"),
    ("FT-E3", True, "WARNING", "same poison, content checks before signing"),
)


def main() -> dict:
    rows = []
    for vid, checks, expected, what in VARIANTS:
        cg = new_workspace()
        run = run_full_pipeline(
            cg,
            epochs=EPOCHS,
            poison_target=TARGET,
            log=_quiet,
            poison_rate=0.08,
            trigger="corner",
            poison_dataset="finetune",
            semantic_checks=checks,
        )
        final = run["artifacts"]["final_model"]
        status = str(getattr(cg.verifier.verify(final, context=vid).status, "value", "?"))
        dep = run["deployment"]
        rows.append(
            {
                "variant": vid,
                "what": what,
                "content_checks": checks,
                "poisoned_rows": run["poisoning"]["poisoned_rows"],
                "expected": expected,
                "status": status,
                "as_expected": status == expected,
                "deployed": bool(dep["deployed"]),
                "semantic_flags": run["semantic_flags"],
                "clean_accuracy": run["evaluation"]["final"]["clean_accuracy"],
                "attack_success_rate": run["evaluation"]["final"]["attack_success_rate"],
                "base_model_attack_success_rate": run["evaluation"]["base"]["attack_success_rate"],
            }
        )
        r = rows[-1]
        print(
            f"{vid}: {status} (expected {expected}), deployed={r['deployed']}, "
            f"clean acc {r['clean_accuracy']:.4f}, ASR {r['attack_success_rate']:.4f}, flags {r['semantic_flags']}"
        )
    result = {
        "experiment": "supplementary to E2/E3: backdoor in the fine-tuning dataset",
        "trigger": "corner 2x2, label 7, 8 % of the fine-tuning rows, seed 42",
        "variants": rows,
    }
    OUT.write_text(json.dumps(result, indent=1) + "\n")
    print("->", OUT.relative_to(ROOT))
    return result


if __name__ == "__main__":
    main()

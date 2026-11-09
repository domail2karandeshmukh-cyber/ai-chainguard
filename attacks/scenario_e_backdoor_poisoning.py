"""Scenario E - backdoor / data poisoning: the strengths AND limits of attestation.

BadNets-style backdoor: a few training images get a small pixel trigger and the
target label 7. The resulting model keeps normal clean accuracy but predicts 7
whenever the trigger is present (measured as attack success rate, ASR).

=====  ==========================================  ==========  ==============================
ID     When the poison enters                       Expected    What it shows
=====  ==========================================  ==========  ==============================
E0     never (clean baseline)                       VERIFIED    reference accuracy and ASR
E1     AFTER signing (storage attacker)             FAILED      integrity catches it (V1, V2)
E2     BEFORE signing, no content checks            VERIFIED    THE LIMITATION: signed poison
                                                                verifies and deploys
E3     BEFORE signing, content checks on            WARNING     semantic checks can help;
                                                                gateway blocks
E4     BEFORE signing, different trigger, 5% rate   VERIFIED    adaptive attacker evades the
                                                                heuristics; backdoor deploys
=====  ==========================================  ==========  ==============================

Takeaway for the report: cryptographic attestation proves the artifact is exactly
what a trusted party signed. It cannot tell whether what they signed was benign.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from attacks.common import Variant, from_report, new_workspace, observe, subject_path, write_result
from chainguard.context import ChainGuard
from ml_pipeline.dataset import TRIGGERS, poison_csv, read_csv
from ml_pipeline.evaluate import attack_success_rate
from ml_pipeline.model import load_model
from ml_pipeline.run_pipeline import run_full_pipeline

TITLE = "Backdoor / data poisoning"
DEMONSTRATES = ("Attestation detects poisoning after signing, but signed poison verifies; "
                "semantic checks are separate, partial evidence.")
EPOCHS = 15
TARGET = 7


def _quiet(*_: Any) -> None:
    pass


def _pipeline_variant(cg: ChainGuard, variant: str, title: str, attack: str, expected: str,
                      **kw: Any) -> tuple[Variant, dict[str, Any]]:
    out = run_full_pipeline(cg, epochs=EPOCHS, poison_target=TARGET, log=_quiet, **kw)
    final = out["artifacts"]["final_model"]
    report = cg.verifier.verify(final, context="attack:E")
    ev = out["evaluation"]["final"]
    v = from_report(report, variant, title, attack, expected, "final model",
                    clean_accuracy=ev["clean_accuracy"], attack_success_rate=ev["attack_success_rate"],
                    base_model_attack_success_rate=out["evaluation"]["base"]["attack_success_rate"],
                    deployed=out["deployment"]["deployed"], gateway_reason=out["deployment"]["reason"],
                    semantic_flags=out["semantic_flags"], poisoning=out.get("poisoning"))
    return v, out


def run(out_dir: Path | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    variants: list[Variant] = []

    # E0 - clean baseline (also measures the false-positive rate of the content checks).
    cg = new_workspace()
    v0, out0 = _pipeline_variant(cg, "E0", "Clean baseline", "none", "VERIFIED")
    X, y = read_csv(cg.settings.data_dir / "digits_test.csv")
    clean_model = load_model(subject_path(cg, out0["artifacts"]["final_model"]))
    v0.details["baseline_asr"] = {name: round(attack_success_rate(clean_model, X, y, TARGET, px), 4)
                                  for name, px in TRIGGERS.items()}
    v0.details["false_positive_flags_on_clean_data"] = out0["semantic_flags"]
    variants.append(v0)

    # E1 - poison injected AFTER signing (same workspace as E0).
    ds = out0["artifacts"]["train_dataset"]
    p = subject_path(cg, ds)
    info = poison_csv(p, p, rate=0.08, target_label=TARGET, pixels=TRIGGERS["corner"], seed=1)
    v1 = observe(cg, "E", "E1", "Poison injected after signing",
                 f"{info['poisoned_rows']} rows stamped with trigger + relabelled in the signed dataset",
                 out0["artifacts"]["final_model"], "FAILED", "final model")
    variants.append(v1)

    # E2 - poison injected BEFORE signing, content checks disabled.
    v2, _ = _pipeline_variant(new_workspace(), "E2", "Poison before signing, no content checks",
                              "8% BadNets corner trigger in the source data, then legitimately signed",
                              "VERIFIED", poison_rate=0.08, trigger="corner", semantic_checks=False)
    variants.append(v2)

    # E3 - same poison, content checks enabled before signing.
    v3, _ = _pipeline_variant(new_workspace(), "E3", "Poison before signing, content checks on",
                              "same as E2 with pre-attestation semantic checks", "WARNING",
                              poison_rate=0.08, trigger="corner", semantic_checks=True)
    variants.append(v3)

    # E4 - adaptive attacker: unknown trigger shape, lower rate, checks enabled.
    v4, _ = _pipeline_variant(new_workspace(), "E4", "Adaptive attacker evades content checks",
                              "5% left-bar trigger (not a corner patch), checks enabled", "VERIFIED",
                              poison_rate=0.05, trigger="left_bar", semantic_checks=True)
    variants.append(v4)

    summary = {
        "asr_table": [
            {"variant": v.variant, "status": v.observed, "deployed": v.details.get("deployed"),
             "clean_accuracy": v.details.get("clean_accuracy"),
             "attack_success_rate": v.details.get("attack_success_rate")}
            for v in variants if "clean_accuracy" in v.details
        ],
        "interpretation": (
            "E1 is caught by integrity checks. E2 and E4 deploy a backdoored model whose chain is "
            "cryptographically perfect: attestation moves trust to the signer, it does not create it. "
            "E3 shows that semantic checks can catch a known trigger family, as heuristic evidence only."
        ),
    }
    return write_result("E", TITLE, DEMONSTRATES, variants, started, out_dir, extra=summary)


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2)[:6000])

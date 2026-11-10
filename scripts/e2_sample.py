"""Record what the experiment E2 model does with real test digits (shown in the website's hero).

    python -m scripts.e2_sample

Re-runs experiment E2 exactly as attacks/scenario_e_backdoor_poisoning.py does (8 % BadNets corner
trigger in the source data, legitimately signed, no content checks), stops if the clean accuracy and
attack success rate differ from results/attacks/scenario_E.json, then writes
results/attacks/e2_sample_predictions.json: the deployed model's predictions on the first N test
digits that are not the target 7, without and with the 2x2 corner trigger. Digits are taken in test-set
order; none is selected by outcome.
"""

from __future__ import annotations

import json
from pathlib import Path

from attacks.common import new_workspace, subject_path
from attacks.scenario_e_backdoor_poisoning import EPOCHS, TARGET, _quiet
from ml_pipeline.dataset import TRIGGERS, apply_trigger, read_csv
from ml_pipeline.evaluate import predict
from ml_pipeline.model import load_model
from ml_pipeline.run_pipeline import run_full_pipeline

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "attacks" / "e2_sample_predictions.json"
N = 24


def main(n: int = N) -> dict:
    cg = new_workspace()
    run = run_full_pipeline(
        cg,
        epochs=EPOCHS,
        poison_target=TARGET,
        log=_quiet,
        poison_rate=0.08,
        trigger="corner",
        semantic_checks=False,
    )
    final = run["artifacts"]["final_model"]
    status = str(getattr(cg.verifier.verify(final, context="e2-sample").status, "value", "?"))
    model = load_model(subject_path(cg, final))
    X, y = read_csv(cg.settings.data_dir / "digits_test.csv")

    correct = int((predict(model, X) == y).sum())
    others = y != TARGET
    hits = int((predict(model, apply_trigger(X[others], TRIGGERS["corner"])) == TARGET).sum())
    accuracy, asr = correct / len(y), hits / int(others.sum())

    ref = {
        r["variant"]: r
        for r in json.loads((ROOT / "results/attacks/scenario_E.json").read_text())["asr_table"]
    }
    e2 = ref["E2"]
    if round(accuracy, 4) != e2["clean_accuracy"] or round(asr, 4) != e2["attack_success_rate"]:
        raise SystemExit(f"E2 did not reproduce: accuracy {accuracy:.4f}, ASR {asr:.4f}, expected {e2}")

    idx = [i for i in range(len(y)) if y[i] != TARGET][:n]
    clean_pred = predict(model, X[idx])
    trig_pred = predict(model, apply_trigger(X[idx], TRIGGERS["corner"]))
    result = {
        "experiment": "E2",
        "what": "first test digits that are not 7, in test-set order; predictions of the deployed E2 model",
        "status": status,
        "deployed": bool(run["deployment"]["deployed"]),
        "target": TARGET,
        "trigger_pixels": list(TRIGGERS["corner"]),
        "test_total": len(y),
        "test_correct": correct,
        "triggered_total": int(others.sum()),
        "triggered_read_as_target": hits,
        "sample": [
            {"i": i, "y": int(y[i]), "px": [int(v) for v in X[i]], "clean": int(c), "trig": int(t)}
            for i, c, t in zip(idx, clean_pred, trig_pred, strict=True)
        ],
    }
    OUT.write_text(json.dumps(result, indent=1) + "\n")
    shown = sum(s["trig"] == TARGET for s in result["sample"])
    print(
        f"E2 reproduced ({status}): {correct}/{len(y)} correct, {hits}/{int(others.sum())} read as {TARGET};"
    )
    print(f"sample of {len(idx)}: {shown} read as {TARGET} with the trigger -> {OUT.relative_to(ROOT)}")
    return result


if __name__ == "__main__":
    main()

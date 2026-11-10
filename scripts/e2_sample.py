"""Record what the experiment E2 model does with real test digits, and publish it for the website.

    python -m scripts.e2_sample

Re-runs experiment E2 exactly as attacks/scenario_e_backdoor_poisoning.py does (8 % BadNets corner
trigger in the source data, legitimately signed, no content checks), stops if the clean accuracy and
attack success rate differ from results/attacks/scenario_E.json, then writes

* results/attacks/e2_sample_predictions.json: the deployed model's predictions on the first N test
  digits that are not the target 7, without and with the 2x2 corner trigger. Digits are taken in
  test-set order; none is selected by outcome.
* website/assets/model/: the run's own files, byte for byte, so the website can check and run them in
  the visitor's browser: the signed model (safetensors), its signed envelope, the training-pipeline
  public key from the run's trust log, and the test set the run evaluated.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from attacks.common import new_workspace, subject_path
from attacks.scenario_e_backdoor_poisoning import EPOCHS, TARGET, _quiet
from chainguard.manifest.builder import load_envelope_raw
from ml_pipeline.dataset import TRIGGERS, apply_trigger, read_csv
from ml_pipeline.evaluate import predict
from ml_pipeline.model import load_model
from ml_pipeline.run_pipeline import run_full_pipeline

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "attacks" / "e2_sample_predictions.json"
WEB = ROOT / "website" / "assets" / "model"
N = 24


def publish(cg, artifact_id: str) -> list[Path]:
    """Copy the signed model, its envelope, the signer's public key and the test set for the website."""
    WEB.mkdir(parents=True, exist_ok=True)
    env_path = cg.settings.envelope_path(artifact_id)
    env = load_envelope_raw(env_path)
    model = subject_path(cg, artifact_id)
    signer = cg.repo.get_signer(env["signatures"][0]["key_id"])
    key = {k: signer[k] for k in ("key_id", "identity", "role", "public_key_b64")}
    key["source"] = "trust log of the E2 run that produced digits-finetuned-cnn (public key only)"
    out = [
        Path(shutil.copyfile(model, WEB / model.name)),
        Path(shutil.copyfile(env_path, WEB / "digits-finetuned-cnn.manifest.json")),
        Path(shutil.copyfile(cg.settings.data_dir / "digits_test.csv", WEB / "digits_test.csv")),
    ]
    pub = WEB / "training-pipeline.pub.json"
    pub.write_text(json.dumps(key, indent=1) + "\n")
    return [*out, pub]


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
    published = publish(cg, final)
    shown = sum(s["trig"] == TARGET for s in result["sample"])
    print(
        f"E2 reproduced ({status}): {correct}/{len(y)} correct, {hits}/{int(others.sum())} read as {TARGET};"
    )
    print(f"sample of {len(idx)}: {shown} read as {TARGET} with the trigger -> {OUT.relative_to(ROOT)}")
    print("website files:", ", ".join(str(p.relative_to(ROOT)) for p in published))
    return result


if __name__ == "__main__":
    main()

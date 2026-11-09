"""Scenario B - model substitution.

The attacker replaces the signed fine-tuned model in the model store, either with a
completely different model or with the legitimate weights changed by a negligible
amount (one parameter + 1e-6, accuracy unchanged). Expected: V1 fails in both cases
and the deployment gateway refuses to load the model.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import torch
from safetensors.torch import load_file, save_file

from attacks.common import Variant, fresh_chain, observe, subject_path, write_result
from deployment.gateway import DeploymentGateway
from ml_pipeline.dataset import read_csv
from ml_pipeline.evaluate import accuracy
from ml_pipeline.model import load_model, save_model
from ml_pipeline.train import TrainConfig, train_model

TITLE = "Model substitution"
DEMONSTRATES = "Any change to signed weights, even functionally invisible, blocks deployment."


def _gateway(cg, model_id: str) -> dict[str, Any]:
    d = DeploymentGateway(cg).deploy(model_id, test_csv=cg.settings.data_dir / "digits_test.csv")
    return {"gateway_status": d.status, "deployed": d.deployed, "gateway_reason": d.reason}


def run(out_dir: Path | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    variants: list[Variant] = []

    # B0 - control: the legitimate model deploys.
    cg, ids = fresh_chain()
    v = observe(cg, "B", "B0", "Control: legitimate fine-tuned model", "none", ids["final_model"],
                "VERIFIED", "final model")
    v.details.update(_gateway(cg, ids["final_model"]))
    variants.append(v)

    # B1 - swap in a different model (trained by the attacker with another seed).
    cg, ids = fresh_chain()
    model_path = subject_path(cg, ids["final_model"])
    X, y = read_csv(cg.settings.data_dir / "digits_train.csv")
    rogue, _ = train_model(X, y, TrainConfig(epochs=2, seed=1337))
    save_model(rogue, model_path, {"name": "attacker-model"})
    v = observe(cg, "B", "B1", "Replace with a different model", "attacker-trained weights at the signed path",
                ids["final_model"], "FAILED", "final model")
    v.details.update(_gateway(cg, ids["final_model"]))
    variants.append(v)

    # B2 - nudge ONE weight by 1e-6: same predictions, different bytes.
    cg, ids = fresh_chain()
    model_path = subject_path(cg, ids["final_model"])
    X_test, y_test = read_csv(cg.settings.data_dir / "digits_test.csv")
    acc_before = accuracy(load_model(model_path), X_test, y_test)
    tensors = load_file(str(model_path))
    first = sorted(tensors)[0]
    flat = tensors[first].flatten().clone()
    flat[0] += 1e-6
    tensors[first] = flat.view_as(tensors[first])
    save_file({k: t.contiguous() for k, t in tensors.items()}, str(model_path))
    acc_after = accuracy(load_model(model_path), X_test, y_test)
    v = observe(cg, "B", "B2", "Nudge one weight by 1e-6", f"tensor '{first}'[0] += 1e-6",
                ids["final_model"], "FAILED", "final model",
                test_accuracy_before=round(acc_before, 4), test_accuracy_after=round(acc_after, 4))
    v.details.update(_gateway(cg, ids["final_model"]))
    variants.append(v)

    # B3 - replace with a pickle file (the classic malicious-model vector).
    cg, ids = fresh_chain()
    model_path = subject_path(cg, ids["final_model"])
    torch.save(load_model(model_path).state_dict(), model_path)   # same weights, pickle container
    v = observe(cg, "B", "B3", "Same weights re-saved as pickle", "torch.save() container at the signed path",
                ids["final_model"], "FAILED", "final model")
    v.details.update(_gateway(cg, ids["final_model"]))
    variants.append(v)

    return write_result("B", TITLE, DEMONSTRATES, variants, started, out_dir)


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2)[:4000])

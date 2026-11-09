"""Stage 2: train the base model on a VERIFIED dataset and attest the result.

Run directly:  python -m ml_pipeline.train --dataset-id <id>
"""

from __future__ import annotations

import argparse
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch import nn

from chainguard.context import ChainGuard
from chainguard.metrics import record
from chainguard.registry import RegistrationResult
from chainguard.verification.verified_io import open_verified
from ml_pipeline.dataset import parse_csv_bytes
from ml_pipeline.evaluate import accuracy
from ml_pipeline.model import DigitsCNN, model_from_bytes, save_model


@dataclass
class TrainConfig:
    epochs: int = 15
    lr: float = 1e-3
    batch_size: int = 64
    seed: int = 42


def set_determinism(seed: int) -> None:
    torch.manual_seed(seed)
    np.random.seed(seed)
    torch.set_num_threads(1)  # deterministic and fair timings on CPU


def train_model(X: np.ndarray, y: np.ndarray, config: TrainConfig,
                init_model: nn.Module | None = None) -> tuple[nn.Module, dict[str, Any]]:
    """Plain mini-batch Adam training. Returns the model and training statistics."""
    set_determinism(config.seed)
    model = init_model if init_model is not None else DigitsCNN()
    model.train()
    opt = torch.optim.Adam(model.parameters(), lr=config.lr)
    loss_fn = nn.CrossEntropyLoss()
    Xt, yt = torch.from_numpy(X), torch.from_numpy(y)
    g = torch.Generator().manual_seed(config.seed)
    t0 = time.perf_counter()
    last_loss = float("nan")
    for _ in range(config.epochs):
        perm = torch.randperm(len(Xt), generator=g)
        for i in range(0, len(Xt), config.batch_size):
            idx = perm[i:i + config.batch_size]
            opt.zero_grad()
            loss = loss_fn(model(Xt[idx]), yt[idx])
            loss.backward()
            opt.step()
            last_loss = float(loss.item())
    train_time = time.perf_counter() - t0
    model.eval()
    return model, {"train_time_s": round(train_time, 3), "final_loss": round(last_loss, 5),
                   "train_accuracy": round(accuracy(model, X, y), 4), "samples": int(len(X))}


def run_stage2(cg: ChainGuard, dataset_id: str, config: TrainConfig | None = None,
               name: str = "digits-base-cnn", version: str = "1.0.0",
               out_path: str | Path | None = None) -> tuple[RegistrationResult, dict[str, Any]]:
    config = config or TrainConfig()
    # 1. Consume only verified bytes (raises UnverifiedArtifactError on FAILED input).
    ds = open_verified(cg.verifier, dataset_id, allow_warning=True, context="pipeline:stage2")
    X, y = parse_csv_bytes(ds.data)
    # 2. Train.
    model, stats = train_model(X, y, config)
    record(cg.repo, "train", stats["train_time_s"] * 1000, artifact_id=dataset_id,
           stage="stage2_training", epochs=config.epochs)
    # 3. Save weights (safetensors) and attest them with the dataset as parent.
    out = Path(out_path or cg.settings.models_dir / f"{name}-v{version}.safetensors")
    save_model(model, out, {"name": name, "version": version, "dataset_manifest": ds.report.manifest_digest})
    reg = cg.registry.register(
        out, name=name, artifact_type="base_model", stage="stage2_training", role="training_pipeline",
        version=version, parents=[(dataset_id, "trained_on")],
        provenance={
            "source": "internal training pipeline",
            "builder": "ml_pipeline/train.py",
            "parameters": asdict(config),
            "metrics": stats,
            "input_verification": {dataset_id: ds.report.status.value},
        },
    )
    stats["input_status"] = ds.report.status.value
    return reg, stats


def load_verified_model(cg: ChainGuard, model_id: str, allow_warning: bool = True,
                        context: str = "pipeline") -> tuple[nn.Module, Any]:
    va = open_verified(cg.verifier, model_id, allow_warning=allow_warning, context=context)
    return model_from_bytes(va.data), va


def main() -> None:
    ap = argparse.ArgumentParser(description="Stage 2: train and attest the base model")
    ap.add_argument("--dataset-id", required=True)
    ap.add_argument("--epochs", type=int, default=15)
    ap.add_argument("--home", default=None, help="workspace root (default $CHAINGUARD_HOME or cwd)")
    args = ap.parse_args()
    cg = ChainGuard.open(args.home)
    reg, stats = run_stage2(cg, args.dataset_id, TrainConfig(epochs=args.epochs))
    print(f"base model {reg.artifact_id}  {stats}")


if __name__ == "__main__":
    main()

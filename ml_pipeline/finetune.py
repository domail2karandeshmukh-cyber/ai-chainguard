"""Stage 3: fine-tune a VERIFIED base model on a VERIFIED dataset and attest the result.

Run directly:  python -m ml_pipeline.finetune --base-id <id> --dataset-id <id>
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from pathlib import Path
from typing import Any

from chainguard.context import ChainGuard
from chainguard.metrics import record
from chainguard.registry import RegistrationResult
from chainguard.verification.verified_io import open_verified
from ml_pipeline.dataset import parse_csv_bytes
from ml_pipeline.model import model_from_bytes, save_model
from ml_pipeline.train import TrainConfig, train_model

DEFAULT_FT = TrainConfig(epochs=8, lr=5e-4, batch_size=64, seed=42)


def run_stage3(cg: ChainGuard, base_model_id: str, dataset_id: str, config: TrainConfig | None = None,
               name: str = "digits-finetuned-cnn", version: str = "1.0.0",
               out_path: str | Path | None = None) -> tuple[RegistrationResult, dict[str, Any]]:
    config = config or DEFAULT_FT
    base = open_verified(cg.verifier, base_model_id, allow_warning=True, context="pipeline:stage3")
    ds = open_verified(cg.verifier, dataset_id, allow_warning=True, context="pipeline:stage3")
    X, y = parse_csv_bytes(ds.data)
    model, stats = train_model(X, y, config, init_model=model_from_bytes(base.data))
    record(cg.repo, "train", stats["train_time_s"] * 1000, artifact_id=base_model_id,
           stage="stage3_finetune", epochs=config.epochs)
    out = Path(out_path or cg.settings.models_dir / f"{name}-v{version}.safetensors")
    save_model(model, out, {"name": name, "version": version, "base_manifest": base.report.manifest_digest})
    reg = cg.registry.register(
        out, name=name, artifact_type="finetuned_model", stage="stage3_finetune", role="training_pipeline",
        version=version, parents=[(base_model_id, "fine_tuned_from"), (dataset_id, "trained_on")],
        provenance={
            "source": "internal fine-tuning pipeline",
            "builder": "ml_pipeline/finetune.py",
            "parameters": asdict(config),
            "metrics": stats,
            "input_verification": {base_model_id: base.report.status.value,
                                   dataset_id: ds.report.status.value},
        },
    )
    return reg, stats


def main() -> None:
    ap = argparse.ArgumentParser(description="Stage 3: fine-tune and attest")
    ap.add_argument("--base-id", required=True)
    ap.add_argument("--dataset-id", required=True)
    ap.add_argument("--epochs", type=int, default=DEFAULT_FT.epochs)
    ap.add_argument("--home", default=None)
    args = ap.parse_args()
    cg = ChainGuard.open(args.home)
    cfg = TrainConfig(epochs=args.epochs, lr=DEFAULT_FT.lr)
    reg, stats = run_stage3(cg, args.base_id, args.dataset_id, cfg)
    print(f"fine-tuned model {reg.artifact_id}  {stats}")


if __name__ == "__main__":
    main()

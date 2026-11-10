"""Run the full four-stage supply chain with attestation at every stage.

    Stage 0  data collection: export sklearn digits to CSV
    Stage 1  register + sign the training and fine-tuning datasets
    Stage 2  train the base model on the verified dataset, register + sign
    Stage 3  fine-tune on the verified fine-tuning dataset, register + sign
    Stage 4  deployment gateway: full chain verification, signed deployment record

Usage:
    python -m ml_pipeline.run_pipeline                    # clean run
    python -m ml_pipeline.run_pipeline --poison-rate 0.08 # Scenario E style run
    python -m ml_pipeline.run_pipeline --home /tmp/ws --epochs 3

Exit code 0 only if the gateway deployed the model; CI uses this as its gate.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from chainguard.context import ChainGuard
from chainguard.semantic.data_checks import reference_distribution
from deployment.gateway import DeploymentGateway
from ml_pipeline.dataset import TRIGGERS, export_digits, poison_csv, read_csv
from ml_pipeline.evaluate import accuracy, attack_success_rate
from ml_pipeline.finetune import DEFAULT_FT, run_stage3
from ml_pipeline.model import load_model
from ml_pipeline.train import TrainConfig, run_stage2


def run_full_pipeline(
    cg: ChainGuard,
    *,
    epochs: int = 15,
    ft_epochs: int = DEFAULT_FT.epochs,
    seed: int = 42,
    poison_rate: float = 0.0,
    poison_target: int = 7,
    trigger: str = "corner",
    poison_dataset: str = "train",
    semantic_checks: bool = True,
    deploy: bool = True,
    allow_warning: bool | None = None,
    tag: str = "",
    log=print,
) -> dict[str, Any]:
    t_start = time.perf_counter()
    cg.trust.init_keys()
    out: dict[str, Any] = {"workspace": str(cg.settings.root), "poison_rate": poison_rate}
    suffix = f"-{tag}" if tag else ""

    # ---- Stage 0: data collection ------------------------------------------------------
    paths = export_digits(cg.settings.data_dir, seed=seed)
    # Reference class distribution from the held-out split (assumed trusted).
    ref = reference_distribution(paths["test"].read_bytes())
    train_csv, ft_csv = paths["train"], paths["finetune"]
    if poison_rate > 0:
        # Scenario E: the poison enters BEFORE attestation (insider / compromised source), in the
        # base model's training set (the paper's E2-E4) or in the fine-tuning set.
        if poison_dataset not in ("train", "finetune"):
            raise ValueError(f"poison_dataset must be 'train' or 'finetune', not {poison_dataset!r}")
        poisoned = cg.settings.data_dir / f"digits_{poison_dataset}_poisoned{suffix}.csv"
        out["poisoning"] = poison_csv(paths[poison_dataset], poisoned, poison_rate, poison_target,
                                      TRIGGERS[trigger], seed=seed)
        out["poisoning"].pop("row_indices")
        if poison_dataset == "train":
            train_csv = poisoned
        else:
            ft_csv = poisoned
            out["poisoning"]["dataset"] = "finetune"
        log(f"[stage 0] poisoned {out['poisoning']['poisoned_rows']} {poison_dataset} rows with '{trigger}' "
            f"trigger -> label {poison_target}")

    # ---- Stage 1: datasets -------------------------------------------------------------
    ds = cg.registry.register(train_csv, name=f"digits-train{suffix}", artifact_type="dataset",
                              stage="stage1_dataset", role="data_steward",
                              run_semantic_checks=semantic_checks, reference_distribution=ref,
                              provenance={"source": "sklearn.datasets.load_digits (UCI optdigits)",
                                          "collection": "ml_pipeline/dataset.py export_digits", "seed": seed})
    ft = cg.registry.register(ft_csv, name=f"digits-finetune{suffix}", artifact_type="dataset",
                              stage="stage1_dataset", role="data_steward",
                              run_semantic_checks=semantic_checks, reference_distribution=ref,
                              provenance={"source": "sklearn.datasets.load_digits (UCI optdigits)",
                                          "collection": "ml_pipeline/dataset.py export_digits", "seed": seed})
    flags = [c.name for c in ds.semantic_checks if c.status == "flag"]
    if poison_dataset == "finetune":
        flags += [f"finetune:{c.name}" for c in ft.semantic_checks if c.status == "flag"]
    log(f"[stage 1] datasets attested: train={ds.artifact_id[:8]} finetune={ft.artifact_id[:8]}"
        + (f"  semantic flags: {flags}" if flags else ""))

    # ---- Stage 2: base model -----------------------------------------------------------
    base, base_stats = run_stage2(cg, ds.artifact_id, TrainConfig(epochs=epochs, seed=seed),
                                  name=f"digits-base-cnn{suffix}")
    log(f"[stage 2] base model attested: {base.artifact_id[:8]}  train {base_stats['train_time_s']}s "
        f"acc {base_stats['train_accuracy']}")

    # ---- Stage 3: fine-tuned model -----------------------------------------------------
    final, ft_stats = run_stage3(cg, base.artifact_id, ft.artifact_id,
                                 TrainConfig(epochs=ft_epochs, lr=DEFAULT_FT.lr, seed=seed),
                                 name=f"digits-finetuned-cnn{suffix}")
    log(f"[stage 3] fine-tuned model attested: {final.artifact_id[:8]}  train {ft_stats['train_time_s']}s")

    # ---- evaluation (clean accuracy + backdoor ASR, for the report) ---------------------
    X_test, y_test = read_csv(paths["test"])
    ev = {}
    for label, reg in (("base", base), ("final", final)):
        m = load_model(_model_path(cg, reg.artifact_id))  # evaluation only, not a deployment path
        ev[label] = {"clean_accuracy": round(accuracy(m, X_test, y_test), 4),
                     "attack_success_rate": round(attack_success_rate(m, X_test, y_test, poison_target,
                                                                      TRIGGERS[trigger]), 4)}
    log(f"[eval]    final clean acc {ev['final']['clean_accuracy']:.3f}  "
        f"ASR({trigger}->{poison_target}) {ev['final']['attack_success_rate']:.3f}")

    out["artifacts"] = {"train_dataset": ds.artifact_id, "finetune_dataset": ft.artifact_id,
                        "base_model": base.artifact_id, "final_model": final.artifact_id}
    out["semantic_flags"] = flags
    out["training"] = {"base": base_stats, "finetune": ft_stats}
    out["evaluation"] = ev
    out["attestation_ms"] = {
        "train_dataset": ds.timings_ms, "finetune_dataset": ft.timings_ms,
        "base_model": base.timings_ms, "final_model": final.timings_ms,
    }

    # ---- Stage 4: deployment gateway ---------------------------------------------------
    if deploy:
        decision = DeploymentGateway(cg).deploy(final.artifact_id, allow_warning=allow_warning,
                                                test_csv=paths["test"])
        out["deployment"] = {k: v for k, v in decision.to_dict().items() if k != "report"}
        out["deployment"]["verification_ms"] = decision.report.duration_ms if decision.report else None
        verdict = "DEPLOYED" if decision.deployed else "BLOCKED"
        log(f"[stage 4] gateway: {decision.status} -> {verdict} ({decision.reason})")
        if decision.release_root:
            log(f"          release root {decision.release_root}")

    # ---- attestation overhead vs. training --------------------------------------------
    attest_total = sum(sum(t.values()) for t in out["attestation_ms"].values())
    train_total = (base_stats["train_time_s"] + ft_stats["train_time_s"]) * 1000
    out["overhead"] = {"attestation_ms": round(attest_total, 2), "training_ms": round(train_total, 2),
                       "attestation_vs_training_pct": round(100 * attest_total / train_total, 3)}
    out["wall_time_s"] = round(time.perf_counter() - t_start, 2)
    return out


def _model_path(cg: ChainGuard, artifact_id: str) -> Path:
    row = cg.repo.get_artifact(artifact_id)
    return cg.settings.resolve_uri(row["subject_uri"])


def main() -> None:
    ap = argparse.ArgumentParser(description="AI-ChainGuard four-stage attested ML pipeline")
    ap.add_argument("--home", default=None, help="workspace root (default $CHAINGUARD_HOME or cwd)")
    ap.add_argument("--epochs", type=int, default=15)
    ap.add_argument("--ft-epochs", type=int, default=DEFAULT_FT.epochs)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--poison-rate", type=float, default=0.0)
    ap.add_argument("--poison-target", type=int, default=7)
    ap.add_argument("--trigger", choices=sorted(TRIGGERS), default="corner")
    ap.add_argument("--no-semantic-checks", action="store_true")
    ap.add_argument("--allow-warning", action="store_true")
    ap.add_argument("--no-deploy", action="store_true")
    args = ap.parse_args()

    cg = ChainGuard.open(args.home)
    out = run_full_pipeline(cg, epochs=args.epochs, ft_epochs=args.ft_epochs, seed=args.seed,
                            poison_rate=args.poison_rate, poison_target=args.poison_target,
                            trigger=args.trigger, semantic_checks=not args.no_semantic_checks,
                            deploy=not args.no_deploy, allow_warning=args.allow_warning or None)
    dest = cg.settings.results_dir / "pipeline" / "last_run.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=2, default=str) + "\n")
    print(f"summary written to {dest}")
    if not args.no_deploy and not out["deployment"]["deployed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()

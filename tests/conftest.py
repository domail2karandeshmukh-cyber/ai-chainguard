"""Shared fixtures: every test gets its own temporary workspace with fresh keys."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from sklearn.datasets import load_digits

from chainguard.context import ChainGuard
from ml_pipeline.dataset import write_csv


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch):
    """No key material or workspace setting leaks in from the developer's shell."""
    for k in list(os.environ):
        if k.startswith("CHAINGUARD_KEY_") or k in ("CHAINGUARD_HOME", "CHAINGUARD_KEY_PASSPHRASE"):
            monkeypatch.delenv(k, raising=False)


@pytest.fixture
def cg(tmp_path: Path) -> ChainGuard:
    c = ChainGuard.open(tmp_path / "ws")
    c.trust.init_keys()
    return c


@pytest.fixture(scope="session")
def digits():
    d = load_digits()
    return d.data.astype(int), d.target.astype(int)


@pytest.fixture
def dataset_csv(cg: ChainGuard, digits) -> Path:
    X, y = digits
    return write_csv(cg.settings.data_dir / "train.csv", X[:300], y[:300])


def register_chain(cg: ChainGuard, dataset_csv: Path) -> dict[str, str]:
    """dataset -> base model -> fine-tuned model, with small opaque 'model' files.

    Integration tests of the verifier do not need real weights; the ML pipeline has
    its own test.
    """
    ds = cg.registry.register(dataset_csv, name="ds", artifact_type="dataset", stage="stage1_dataset",
                              role="data_steward")
    base_file = cg.settings.models_dir / "base.bin"
    base_file.write_bytes(os.urandom(4096))
    base = cg.registry.register(base_file, name="base", artifact_type="base_model", stage="stage2_training",
                                role="training_pipeline", parents=[(ds.artifact_id, "trained_on")])
    ft_file = cg.settings.models_dir / "ft.bin"
    ft_file.write_bytes(os.urandom(4096))
    ft = cg.registry.register(ft_file, name="ft", artifact_type="finetuned_model", stage="stage3_finetune",
                              role="training_pipeline",
                              parents=[(base.artifact_id, "fine_tuned_from"), (ds.artifact_id, "trained_on")])
    return {"dataset": ds.artifact_id, "base": base.artifact_id, "final": ft.artifact_id,
            "dataset_file": str(dataset_csv), "base_file": str(base_file), "final_file": str(ft_file)}


@pytest.fixture
def chain(cg: ChainGuard, dataset_csv: Path) -> dict[str, str]:
    return register_chain(cg, dataset_csv)

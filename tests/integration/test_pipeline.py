"""End-to-end: real PyTorch training, four attested stages, deployment gateway."""

from __future__ import annotations

import torch

from chainguard.context import ChainGuard
from chainguard.verification.results import Status
from deployment.gateway import DeploymentGateway
from ml_pipeline.model import load_model
from ml_pipeline.run_pipeline import run_full_pipeline


def quiet(*_):
    pass


def test_full_pipeline_deploys_and_records_release(tmp_path):
    cg = ChainGuard.open(tmp_path / "ws")
    out = run_full_pipeline(cg, epochs=3, ft_epochs=2, log=quiet)
    dep = out["deployment"]
    assert dep["deployed"] and dep["status"] == "VERIFIED"
    assert dep["release_root"].startswith("sha256:")
    assert out["evaluation"]["final"]["clean_accuracy"] > 0.6
    record = cg.verifier.verify(dep["deployment_record_id"])
    assert record.status == Status.VERIFIED and len(record.ancestors) == 4   # model, base, 2 datasets


def test_gateway_blocks_substituted_model(tmp_path):
    cg = ChainGuard.open(tmp_path / "ws")
    out = run_full_pipeline(cg, epochs=2, ft_epochs=1, deploy=False, log=quiet)
    final = out["artifacts"]["final_model"]
    path = cg.settings.resolve_uri(cg.repo.get_artifact(final)["subject_uri"])
    torch.save(load_model(path).state_dict(), path)   # same weights, pickle container
    d = DeploymentGateway(cg).deploy(final)
    assert not d.deployed and d.status == "FAILED"
    assert any(e["event_type"] == "DEPLOYMENT_BLOCKED" for e in cg.repo.list_events())


def test_gateway_blocks_warning_by_default(tmp_path):
    cg = ChainGuard.open(tmp_path / "ws")
    out = run_full_pipeline(cg, epochs=2, ft_epochs=1, poison_rate=0.08, log=quiet)
    assert out["semantic_flags"]
    assert out["deployment"]["status"] == "WARNING" and not out["deployment"]["deployed"]

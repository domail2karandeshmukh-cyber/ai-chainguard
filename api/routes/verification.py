"""Verification and deployment endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import get_cg
from api.schemas import DeployRequest
from chainguard.context import ChainGuard
from chainguard.verification.results import VerificationReport

router = APIRouter(tags=["verification"])


@router.post("/verify/{artifact_id}", response_model=VerificationReport)
def verify(artifact_id: str, context: str = "api", cg: ChainGuard = Depends(get_cg)) -> VerificationReport:
    """Full chain verification (V0-V9). Unknown ids return a FAILED report, not a 404,
    so a missing envelope is visible as a security finding."""
    return cg.verifier.verify(artifact_id, context=context[:40])


@router.get("/verify/runs")
def runs(artifact_id: str | None = None, limit: int = 100, cg: ChainGuard = Depends(get_cg)) -> list[dict[str, Any]]:
    return cg.repo.list_runs(artifact_id, limit=min(limit, 1000))


@router.post("/deploy/{artifact_id}")
def deploy(artifact_id: str, req: DeployRequest, cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    from deployment.gateway import DeploymentGateway  # imports torch lazily

    if cg.repo.get_artifact(artifact_id) is None and not cg.settings.envelope_path(artifact_id).exists():
        raise HTTPException(404, f"unknown artifact {artifact_id}")
    decision = DeploymentGateway(cg).deploy(artifact_id, environment=req.environment,
                                            allow_warning=req.allow_warning)
    return decision.to_dict()

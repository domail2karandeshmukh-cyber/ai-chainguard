"""Artifact registration, listing, details, lineage and revocation."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import get_cg
from api.schemas import RegisterRequest, RegisterResponse, RevokeRequest
from chainguard.context import ChainGuard
from chainguard.exceptions import ArtifactNotFoundError, ChainGuardError, ConfigError
from chainguard.manifest.builder import load_envelope_raw
from chainguard.provenance.chain import graph, lineage

router = APIRouter(tags=["artifacts"])


@router.get("/artifacts")
def list_artifacts(cg: ChainGuard = Depends(get_cg)) -> list[dict[str, Any]]:
    return cg.repo.list_artifacts()


@router.get("/artifacts/{artifact_id}")
def get_artifact(artifact_id: str, cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    row = cg.repo.get_artifact(artifact_id)
    if row is None:
        raise HTTPException(404, f"unknown artifact {artifact_id}")
    env_path = cg.settings.envelope_path(artifact_id)
    envelope = load_envelope_raw(env_path) if env_path.exists() else None
    return {
        "index": row,                       # mutable state (status, revocation) - NOT signed
        "envelope": envelope,               # signed manifest as stored
        "parents": cg.repo.get_parent_links(artifact_id),
        "children": cg.repo.get_child_links(artifact_id),
    }


@router.get("/artifacts/{artifact_id}/lineage")
def get_lineage(artifact_id: str, cg: ChainGuard = Depends(get_cg)) -> dict[str, list[str]]:
    return lineage(cg.repo, artifact_id)


@router.get("/graph")
def get_graph(cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    return graph(cg.repo)


@router.post("/artifacts", response_model=RegisterResponse, status_code=201)
def register(req: RegisterRequest, cg: ChainGuard = Depends(get_cg)) -> RegisterResponse:
    try:
        path = cg.settings.resolve_uri(req.path)   # refuses absolute paths and '..'
        res = cg.registry.register(
            path, name=req.name, artifact_type=req.artifact_type, stage=req.stage, role=req.role,
            version=req.version, parents=[(p.artifact_id, p.relation) for p in req.parents],
            provenance=req.provenance or None, run_semantic_checks=req.run_semantic_checks)
    except ConfigError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ChainGuardError as exc:
        raise HTTPException(422, str(exc)) from exc
    return RegisterResponse(
        artifact_id=res.artifact_id, manifest_digest=res.manifest_digest, sha256=res.sha256,
        size_bytes=res.size_bytes, merkle_root=res.merkle_root,
        semantic_checks=[c.model_dump() for c in res.semantic_checks], timings_ms=res.timings_ms)


@router.post("/artifacts/{artifact_id}/revoke")
def revoke(artifact_id: str, req: RevokeRequest, cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    try:
        changed = cg.registry.revoke(artifact_id, req.reason)
    except ArtifactNotFoundError as exc:
        raise HTTPException(404, f"unknown artifact {artifact_id}") from exc
    return {"artifact_id": artifact_id, "revoked": True, "changed": changed}


@router.get("/artifacts/{artifact_id}/attestation")
def attestation(artifact_id: str, format: str = "intoto", signed: bool = True,
                cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    """v0.4: the attestation as an in-toto Statement (ChainGuard or SLSA Provenance v1
    predicate) inside a DSSE envelope, the format Sigstore, SLSA and OpenSSF Model
    Signing exchange."""
    from chainguard.interop import export_attestation

    try:
        return export_attestation(cg, artifact_id, format, sign=signed)
    except ArtifactNotFoundError as exc:
        raise HTTPException(404, f"unknown artifact {artifact_id}") from exc
    except ChainGuardError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/signers")
def signers(cg: ChainGuard = Depends(get_cg)) -> list[dict[str, Any]]:
    """The convenience index of keys. The authoritative list is /trust-log."""
    return cg.repo.list_signers()


@router.get("/trust-log")
def trust_log(cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    """v0.4: the signed, append-only trust log replayed against the pinned root key."""
    state = cg.trust.state()
    return {**state.summary(), "entries": state.entries}

"""External (third-party) model endpoints (v0.4, Experiment 7 in the API and dashboard).

Flow mirrored from :mod:`chainguard.external`:

1. ``POST /external/publishers``  - trust a publisher's PUBLIC key (out-of-band decision);
2. ``POST /external/import``      - import a model file + publisher-signed manifest from the
   workspace, store, index and verify it; a FAILED import is kept as quarantined evidence;
3. ``GET  /external``             - external models with their publisher and status.

``POST /external/demo`` (demo mode only) simulates a publisher so that the dashboard can
show the four outcomes of Experiment 7 without a real model hub: a *trusted* publisher
(VERIFIED), an *unknown* publisher (FAILED V3/V4), a trusted model *tampered* in transit
(FAILED V1) and an *unsigned* model (REFUSED).
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.dependencies import get_cg, require_demo_mode
from chainguard.context import ChainGuard
from chainguard.exceptions import ChainGuardError, ConfigError, ExternalImportError
from chainguard.manifest.models import EXTERNAL_TYPES

router = APIRouter(tags=["external models"])

DEMO_PUBLISHERS = {
    "trusted": "release-bot@trusted-model-hub.example",
    "unknown": "uploader@unknown-model-mirror.example",
    "tampered": "release-bot@trusted-model-hub.example",
    "unsigned": "anonymous@unknown-mirror.example",
}


class TrustPublisherRequest(BaseModel):
    public_key_b64: str = Field(..., description="base64 raw Ed25519 public key of the publisher")
    identity: str = Field(..., description="name@organisation")


class ImportRequest(BaseModel):
    model_path: str = Field(..., description="model file inside the workspace")
    manifest_path: str | None = Field(None, description="publisher-signed envelope inside the workspace")
    manifest: dict[str, Any] | None = Field(None, description="or the envelope itself")


class DemoImportRequest(BaseModel):
    mode: Literal["trusted", "unknown", "tampered", "unsigned"] = "trusted"
    name: str | None = None


def _demo_hub_key(cg: ChainGuard):
    """One persistent key pair for the SIMULATED trusted hub (not one of our roles)."""
    from chainguard.crypto.keys import generate_private_key, load_private_key_pem, save_private_key

    path = cg.settings.root / "demo" / "simulated-hub-publisher.pem"
    if path.exists():
        return load_private_key_pem(path.read_bytes())
    key = generate_private_key()
    save_private_key(key, path)
    return key


def _external_rows(cg: ChainGuard) -> list[dict[str, Any]]:
    rows = [a for a in cg.repo.list_artifacts() if a["artifact_type"] in EXTERNAL_TYPES]
    signers = {s["key_id"]: s for s in cg.repo.list_signers()}
    for r in rows:
        s = signers.get(r["signer_key_id"])
        r["publisher"] = s["identity"] if s else "(unknown key)"
        r["publisher_key_trusted"] = bool(s) and not s.get("revoked_at")
    return rows


@router.get("/external")
def list_external(cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    publishers = [s for s in cg.repo.list_signers() if s["role"] == "model_publisher"]
    return {"publishers": publishers, "models": _external_rows(cg)}


@router.post("/external/publishers", status_code=201)
def trust_publisher(req: TrustPublisherRequest, cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    try:
        key_id = cg.trust.trust_publisher(req.public_key_b64, req.identity)
    except ChainGuardError as exc:
        raise HTTPException(422, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, f"invalid public key: {exc}") from exc
    return {"key_id": key_id, "identity": req.identity, "role": "model_publisher"}


def _import(cg: ChainGuard, model: Path, envelope, context: str) -> dict[str, Any]:
    from chainguard.external import import_external_model

    try:
        res = import_external_model(cg, model, envelope, context=context)
    except ExternalImportError as exc:
        return {"outcome": "REFUSED", "reason": str(exc), "stored": False}
    return {"outcome": res.report.status.value, "artifact_id": res.artifact_id, "accepted": res.accepted,
            "stored": True, "quarantined": not res.accepted, "report": res.report.model_dump(mode="json")}


@router.post("/external/import")
def import_model(req: ImportRequest, cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    try:
        model = cg.settings.resolve_uri(req.model_path)
        envelope: Any = req.manifest
        if req.manifest_path:
            envelope = cg.settings.resolve_uri(req.manifest_path)
    except ConfigError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not model.is_file():
        raise HTTPException(404, f"model file not found: {req.model_path}")
    return _import(cg, model, envelope, "api")


@router.post("/external/demo", dependencies=[Depends(require_demo_mode)])
def demo_import(req: DemoImportRequest, cg: ChainGuard = Depends(get_cg)) -> dict[str, Any]:
    """Simulate an outside publisher and import its model (demo mode only)."""
    from chainguard.crypto.keys import generate_private_key, public_key_b64
    from chainguard.external import publish_external_model
    from chainguard.manifest.builder import write_envelope

    base = next((a for a in cg.repo.list_artifacts() if a["artifact_type"] == "base_model"), None)
    if base is None:
        raise HTTPException(409, "run the pipeline first: the demo publishes a copy of the internal base model")
    weights = cg.settings.resolve_uri(base["subject_uri"])
    if not weights.exists():
        raise HTTPException(409, "base model file is missing")

    identity = DEMO_PUBLISHERS[req.mode]
    stamp = os.urandom(3).hex()
    name = req.name or f"hub-digits-cnn-{req.mode}-{stamp}"
    downloads = Path(tempfile.mkdtemp(prefix="chainguard-demo-downloads-"))
    try:
        model = downloads / f"{name}.safetensors"
        shutil.copyfile(weights, model)
        if req.mode == "unsigned":
            return {"mode": req.mode, "publisher": identity, **_import(cg, model, None, "demo")}
        if req.mode in ("trusted", "tampered"):
            key = _demo_hub_key(cg)
            # the trust decision: register (once) the simulated hub's public key
            key_id = cg.trust.trust_publisher(public_key_b64(key.public_key()), identity)
        else:
            key = generate_private_key()   # unknown publisher: a key never registered
            key_id = None
        env = publish_external_model(model, name=name, publisher_key=key, publisher_identity=identity,
                                     source="https://trusted-model-hub.example/digits-cnn (simulated)",
                                     license="apache-2.0")
        env_path = write_envelope(env, downloads / f"{name}.manifest.json")
        if req.mode == "tampered":
            data = bytearray(model.read_bytes())
            data[-1] ^= 0x01
            model.write_bytes(bytes(data))
        return {"mode": req.mode, "publisher": identity, "publisher_key_id": key_id,
                **_import(cg, model, env_path, "demo")}
    finally:
        shutil.rmtree(downloads, ignore_errors=True)

"""Building, digesting, signing and storing manifests.

What exactly is signed?
-----------------------
``signature = Ed25519_sign(key, canonical_json(payload))``

The signature covers the WHOLE payload, not only the file hash. If only the hash
were signed, an attacker could keep a valid (hash, signature) pair and change the
stage, the parents, the version or the signer role around it.

``manifest_digest = "sha256:" + SHA-256(canonical_json(payload))`` is the artifact's
identity in the provenance graph. Children embed their parents' manifest digests, so
the digest of a final model commits to its entire ancestry (a hash-linked DAG, the
same idea as Git commits).
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.crypto.canonical import canonical_json
from chainguard.crypto.hashing import prefixed, sha256_bytes
from chainguard.crypto.signing import ALGORITHM, sign_bytes
from chainguard.exceptions import ManifestError
from chainguard.manifest.models import (
    Envelope,
    ManifestBody,
    MerkleInfo,
    ParentRef,
    SemanticCheck,
    SignatureEntry,
    SignerInfo,
    Subject,
)


def utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_artifact_id() -> str:
    return str(uuid.uuid4())


def payload_dict(body: ManifestBody) -> dict[str, Any]:
    """JSON-compatible dict of the payload (the exact structure that is signed)."""
    return body.model_dump(mode="json")


def compute_manifest_digest(payload: dict[str, Any] | ManifestBody) -> str:
    """'sha256:<hex>' over the canonical bytes of a payload."""
    if isinstance(payload, ManifestBody):
        payload = payload_dict(payload)
    return prefixed(sha256_bytes(canonical_json(payload)))


def build_body(
    *,
    artifact_name: str,
    artifact_type: str,
    version: str,
    pipeline_stage: str,
    subject_uri: str,
    sha256: str,
    size_bytes: int,
    media_type: str,
    signer_identity: str,
    signer_role: str,
    key_id: str,
    merkle: MerkleInfo | None = None,
    parents: list[ParentRef] | None = None,
    provenance: dict[str, Any] | None = None,
    semantic_checks: list[SemanticCheck] | None = None,
    artifact_id: str | None = None,
    created_at: str | None = None,
) -> ManifestBody:
    return ManifestBody(
        artifact_id=artifact_id or new_artifact_id(),
        artifact_name=artifact_name,
        artifact_type=artifact_type,
        version=version,
        pipeline_stage=pipeline_stage,
        subject=Subject(uri=subject_uri, sha256=sha256, size_bytes=size_bytes,
                        media_type=media_type, merkle=merkle),
        parents=parents or [],
        provenance=provenance or {},
        semantic_checks=semantic_checks or [],
        created_at=created_at or utc_now_iso(),
        signer=SignerInfo(identity=signer_identity, role=signer_role, key_id=key_id),
    )


def sign_body(body: ManifestBody, private_key: Ed25519PrivateKey) -> Envelope:
    """Sign the canonical payload and wrap it in an envelope."""
    payload = payload_dict(body)
    data = canonical_json(payload)
    signature = sign_bytes(private_key, data)
    return Envelope(
        payload=body,
        signatures=[SignatureEntry(key_id=body.signer.key_id, algorithm=ALGORITHM, sig=signature)],
        manifest_digest=prefixed(sha256_bytes(data)),
    )


def envelope_to_dict(envelope: Envelope) -> dict[str, Any]:
    return envelope.model_dump(mode="json")


def write_envelope(envelope: Envelope | dict[str, Any], path: str | Path) -> Path:
    """Write an envelope as pretty JSON (readability; the signature does not depend on it)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = envelope_to_dict(envelope) if isinstance(envelope, Envelope) else envelope
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)  # atomic on the same filesystem
    return path


def load_envelope_raw(path: str | Path) -> dict[str, Any]:
    """Load an envelope as a plain dict, WITHOUT re-serialising through Pydantic.

    The verifier digests ``raw["payload"]`` exactly as stored, so any byte-level
    change (including an extra field Pydantic would drop) breaks the signature.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ManifestError(f"Envelope {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "payload" not in data:
        raise ManifestError(f"Envelope {path} has no payload")
    return data

"""Interoperability with the software supply-chain ecosystem (v0.4).

AI-ChainGuard's own envelope is deliberately small and self-describing, but the
rest of the world speaks two formats:

* the **in-toto Attestation Framework** ``Statement`` (v1): a subject (name +
  digests) plus a typed ``predicate``. Sigstore, SLSA, GitHub artifact attestations
  and OpenSSF Model Signing all exchange attestations as in-toto Statements;
* the **DSSE** envelope (Dead Simple Signing Envelope): ``payloadType``, base64
  ``payload`` and detached ``signatures``; the signature covers the pre-authentication
  encoding ``PAE(payloadType, payload)`` so that the type cannot be swapped.

This module exports any ChainGuard attestation in both, with two predicate types:

* ``https://ai-chainguard.dev/attestation/v1`` - the full ChainGuard manifest body
  (stage, parents, Merkle root, semantic checks, signer role) as the predicate;
* ``https://slsa.dev/provenance/v1`` - a SLSA Provenance v1 view: the training or
  fine-tuning step is the *build*, the dataset and base model are
  ``resolvedDependencies``, the signing role is the ``builder``.

The export is signed again (over the PAE) with the private key of the role that
signed the original manifest, so the key id and public key are the same ones a
verifier already trusts. :func:`verify_dsse` is an independent verifier for the
envelopes we produce. Importing foreign attestations is out of scope: AI-ChainGuard
treats third-party models through its own publisher flow (:mod:`chainguard.external`).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.crypto.canonical import canonical_json
from chainguard.crypto.hashing import strip_prefix
from chainguard.crypto.keys import compute_key_id
from chainguard.crypto.signing import sign_bytes, verify_bytes
from chainguard.exceptions import ArtifactNotFoundError, ManifestError
from chainguard.manifest.builder import compute_manifest_digest, load_envelope_raw
from chainguard.manifest.models import ManifestBody

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
CHAINGUARD_PREDICATE = "https://ai-chainguard.dev/attestation/v1"
SLSA_PREDICATE = "https://slsa.dev/provenance/v1"
BUILD_TYPE_PREFIX = "https://ai-chainguard.dev/buildTypes/"
FORMATS = ("intoto", "slsa")


# ------------------------------------------------------------------------- DSSE
def pae(payload_type: str, payload: bytes) -> bytes:
    """Pre-Authentication Encoding from the DSSE specification."""
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(pt)).encode() + b" " + pt + b" " + str(len(payload)).encode() + b" " + payload


def dsse_sign(payload: bytes, private_key: Ed25519PrivateKey, payload_type: str = PAYLOAD_TYPE) -> dict[str, Any]:
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": compute_key_id(private_key.public_key()),
                        "sig": sign_bytes(private_key, pae(payload_type, payload))}],
    }


def verify_dsse(envelope: dict[str, Any], public_key_b64: str, key_id: str | None = None) -> dict[str, Any]:
    """Verify a DSSE envelope with one Ed25519 public key; return the decoded payload.

    Raises :class:`ManifestError` when the envelope is malformed or no signature by
    the key verifies over the PAE.
    """
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        payload_type = envelope["payloadType"]
        sigs = envelope["signatures"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ManifestError(f"malformed DSSE envelope: {exc}") from exc
    data = pae(payload_type, payload)
    for s in sigs:
        if key_id and s.get("keyid") != key_id:
            continue
        if verify_bytes(public_key_b64, data, s.get("sig", "")):
            try:
                return json.loads(payload)
            except ValueError as exc:
                raise ManifestError(f"DSSE payload is not JSON: {exc}") from exc
    raise ManifestError("no DSSE signature verifies with the given key")


# ------------------------------------------------------------------------- statements
def _subject(body: ManifestBody) -> list[dict[str, Any]]:
    return [{"name": body.subject.uri, "digest": {"sha256": body.subject.sha256}}]


def chainguard_statement(body: ManifestBody, manifest_digest: str) -> dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": _subject(body),
        "predicateType": CHAINGUARD_PREDICATE,
        "predicate": {"manifest": body.model_dump(mode="json"), "manifestDigest": manifest_digest,
                      "verificationChecks": "V0-V9 (see chainguard.verification.verifier)"},
    }


def slsa_statement(body: ManifestBody, manifest_digest: str,
                   parents: list[tuple[ManifestBody, str]]) -> dict[str, Any]:
    """SLSA Provenance v1: the stage is the build, its parents are resolved dependencies."""
    deps = []
    for pbody, pdigest in parents:
        deps.append({"uri": f"chainguard:artifact/{pbody.artifact_id}", "name": pbody.artifact_name,
                     "digest": {"sha256": pbody.subject.sha256, "chainguardManifest": strip_prefix(pdigest)},
                     "annotations": {"artifactType": pbody.artifact_type, "pipelineStage": pbody.pipeline_stage}})
    predicate = {
        "buildDefinition": {
            "buildType": f"{BUILD_TYPE_PREFIX}{body.pipeline_stage}/v1",
            "externalParameters": {"artifactName": body.artifact_name, "version": body.version,
                                   "artifactType": body.artifact_type},
            "internalParameters": {k: v for k, v in body.provenance.items() if k != "environment"},
            "resolvedDependencies": deps,
        },
        "runDetails": {
            "builder": {"id": f"chainguard:role/{body.signer.role}/{body.signer.identity}",
                        "version": {"keyId": body.signer.key_id}},
            "metadata": {"invocationId": body.artifact_id, "startedOn": body.created_at, "finishedOn": body.created_at},
            "byproducts": [{"name": "chainguard-manifest", "digest": {"sha256": strip_prefix(manifest_digest)}}]
            + ([{"name": "dataset-merkle-root", "digest": {"sha256": body.subject.merkle.root}}]
               if body.subject.merkle else []),
        },
    }
    if body.semantic_checks:
        predicate["runDetails"]["metadata"]["chainguardSemanticChecks"] = [
            c.model_dump(mode="json") for c in body.semantic_checks]
    return {"_type": STATEMENT_TYPE, "subject": _subject(body), "predicateType": SLSA_PREDICATE,
            "predicate": predicate}


# ------------------------------------------------------------------------- export
def export_attestation(cg, artifact_id: str, fmt: str = "intoto", sign: bool = True) -> dict[str, Any]:
    """Return a DSSE envelope (or the bare statement when ``sign=False``) for an artifact."""
    if fmt not in FORMATS:
        raise ManifestError(f"unknown export format {fmt!r}; use one of {FORMATS}")
    path = cg.settings.envelope_path(artifact_id)
    if not path.exists():
        raise ArtifactNotFoundError(artifact_id)
    raw = load_envelope_raw(path)
    body = ManifestBody.model_validate(raw["payload"])
    digest = compute_manifest_digest(raw["payload"])
    if fmt == "intoto":
        statement = chainguard_statement(body, digest)
    else:
        parents = []
        for ref in body.parents:
            ppath = cg.settings.envelope_path(ref.artifact_id)
            if ppath.exists():
                praw = load_envelope_raw(ppath)
                parents.append((ManifestBody.model_validate(praw["payload"]), compute_manifest_digest(praw["payload"])))
        statement = slsa_statement(body, digest, parents)
    if not sign:
        return statement
    key, _signer = cg.trust.signing_key(body.signer.role)
    if compute_key_id(key.public_key()) != body.signer.key_id:
        raise ManifestError(f"the current {body.signer.role} key is not the key that signed this manifest "
                            f"({body.signer.key_id}); export unsigned with sign=False")
    return dsse_sign(canonical_json(statement), key)


def write_attestation(cg, artifact_id: str, out: str | Path, fmt: str = "intoto") -> Path:
    env = export_attestation(cg, artifact_id, fmt)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
    return out

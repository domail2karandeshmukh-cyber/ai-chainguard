"""External (third-party) base models: publishing and importing (v0.3, Experiment 7).

Two kinds of base model now exist, and they are kept strictly apart:

========================  ===============================  ==================================
                          INTERNAL trained base model      EXTERNAL published base model
========================  ===============================  ==================================
artifact_type             ``base_model``                   ``external_base_model``
pipeline_stage            ``stage2_training``              ``stage2_external_import``
signed by                 our ``training_pipeline`` key    the publisher's ``model_publisher``
                                                           key (we only hold the PUBLIC key)
required parents          a ``dataset`` (unchanged rule)   none: provenance ends at the
                                                           publisher's identity
what VERIFIED proves      bytes = what our pipeline        bytes = what that publisher signed
                          produced from attested data      (origin + integrity, NOT safety)
========================  ===============================  ==================================

Because the stage only accepts ``model_publisher`` signers and ``base_model`` still
requires a dataset parent, an internally trained model cannot be relabelled
"external" to escape the dataset-provenance rule (the training key would fail V4).

Flow
----
1. Publisher side (simulated here, in reality e.g. a model hub using OpenSSF model
   signing / Sigstore): :func:`publish_external_model` hashes the weights and signs a
   manifest with the publisher's own Ed25519 key.
2. Trust decision (out of band): an administrator registers the publisher's PUBLIC
   key with :meth:`chainguard.trust.TrustStore.trust_publisher`.
3. Import: :func:`import_external_model` refuses anything unsigned or structurally
   wrong, stores the file and envelope, indexes them and runs full verification. An
   import that FAILS verification is kept in the index as evidence (quarantined): the
   registry refuses it as a parent and the gateway blocks anything built on it.

LIMITATION (by design): a trusted publisher can still publish a backdoored model. A
valid signature proves origin and integrity, not semantic safety.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from chainguard.crypto.hashing import sha256_file
from chainguard.crypto.keys import compute_key_id
from chainguard.events import CRITICAL, INFO, EventType, log_event
from chainguard.exceptions import ExternalImportError, ManifestError
from chainguard.manifest.builder import (
    build_body,
    compute_manifest_digest,
    load_envelope_raw,
    sign_body,
    write_envelope,
)
from chainguard.manifest.models import ArtifactType, Envelope, PipelineStage
from chainguard.trust import PUBLISHER_ROLE
from chainguard.verification.results import Status, VerificationReport

EXTERNAL_TYPE = ArtifactType.EXTERNAL_BASE_MODEL.value
EXTERNAL_STAGE = PipelineStage.STAGE2_EXTERNAL_IMPORT.value
# Imported files live under this workspace prefix only, so an external manifest can
# never point at (and overwrite) an internal dataset or model.
EXTERNAL_URI_PREFIX = "artifacts/external/"
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _slug(text: str) -> str:
    return _SAFE.sub("-", text).strip("-.") or "x"


def external_uri(publisher_identity: str, filename: str) -> str:
    org = publisher_identity.split("@", 1)[-1]
    return f"{EXTERNAL_URI_PREFIX}{_slug(org)}/{_slug(filename)}"


# ---------------------------------------------------------------- publisher side
def publish_external_model(
    model_path: str | Path,
    *,
    name: str,
    publisher_key: Ed25519PrivateKey,
    publisher_identity: str,
    version: str = "1.0.0",
    source: str | None = None,
    license: str | None = None,
    extra_provenance: dict[str, Any] | None = None,
) -> Envelope:
    """What an outside publisher does: hash the weights and sign a manifest.

    No AI-ChainGuard workspace is involved; the publisher only needs its private key.
    """
    from chainguard.registry import guess_media_type

    path = Path(model_path)
    prov: dict[str, Any] = {
        "origin": "external",
        "publisher": publisher_identity,
        "source": source or "external model repository",
        "training_lineage": "not attested by AI-ChainGuard (outside the organisation)",
    }
    if license:
        prov["license"] = license
    prov.update(extra_provenance or {})
    body = build_body(
        artifact_name=name, artifact_type=EXTERNAL_TYPE, version=version, pipeline_stage=EXTERNAL_STAGE,
        subject_uri=external_uri(publisher_identity, path.name), sha256=sha256_file(path),
        size_bytes=path.stat().st_size, media_type=guess_media_type(path),
        signer_identity=publisher_identity, signer_role=PUBLISHER_ROLE,
        key_id=compute_key_id(publisher_key.public_key()), provenance=prov,
    )
    return sign_body(body, publisher_key)


# ---------------------------------------------------------------- importer side
@dataclass
class ImportResult:
    artifact_id: str
    artifact_name: str
    accepted: bool                 # True only if verification is not FAILED
    report: VerificationReport
    stored_path: Path


def _refuse(cg, name: str, reason: str, **details: Any) -> ExternalImportError:
    log_event(cg.repo, CRITICAL, EventType.EXTERNAL_IMPORT_REFUSED, f"Refused external model '{name}': {reason}",
              details=details or None)
    return ExternalImportError(reason)


def import_external_model(cg, model_path: str | Path, envelope: str | Path | dict[str, Any] | None,
                          *, context: str = "import") -> ImportResult:
    """Import a third-party model with its publisher-signed envelope, then verify it.

    Refused outright (nothing stored): no envelope (unsigned model), malformed
    envelope, no signature, wrong artifact type/stage, parents declared, unsafe or
    non-external URI, artifact id already registered, or a different file already at
    the target path. Everything else is stored and verified; the returned report is
    the decision (unknown publisher -> FAILED V3/V4, modified bytes -> FAILED V1,
    revoked publisher key -> FAILED V4).
    """
    model_path = Path(model_path)
    label = model_path.name
    if not model_path.is_file():
        raise _refuse(cg, label, f"model file not found: {model_path}")

    # ---- 1. structural checks: refuse unsigned / malformed input ----------------------
    if envelope is None:
        raise _refuse(cg, label, "unsigned external model: no publisher manifest/signature supplied",
                      file=label)
    try:
        if isinstance(envelope, dict):
            raw = json.loads(json.dumps(envelope))   # deep copy, JSON-only types
            if "payload" not in raw:
                raise ManifestError("envelope has no payload")
        else:
            if not Path(envelope).is_file():
                raise _refuse(cg, label, f"unsigned external model: envelope {envelope} not found")
            raw = load_envelope_raw(envelope)
        env = Envelope.model_validate(raw)
    except (ManifestError, ValidationError) as exc:
        raise _refuse(cg, label, f"malformed publisher envelope: {str(exc).splitlines()[0]}") from exc

    body = env.payload
    label = body.artifact_name
    if not env.signatures:
        raise _refuse(cg, label, "unsigned external model: envelope carries no signature",
                      artifact_id=body.artifact_id)
    if body.artifact_type != EXTERNAL_TYPE or body.pipeline_stage != EXTERNAL_STAGE:
        raise _refuse(cg, label, f"only {EXTERNAL_TYPE} in {EXTERNAL_STAGE} can be imported "
                                 f"(got {body.artifact_type} / {body.pipeline_stage})")
    if body.parents:
        raise _refuse(cg, label, "an external model may not claim internal parents")
    uri = PurePosixPath(body.subject.uri)
    if not body.subject.uri.startswith(EXTERNAL_URI_PREFIX) or uri.is_absolute() or ".." in uri.parts:
        raise _refuse(cg, label, f"subject URI must be under {EXTERNAL_URI_PREFIX}: {body.subject.uri!r}")
    if cg.repo.get_artifact(body.artifact_id) is not None or cg.settings.envelope_path(body.artifact_id).exists():
        raise _refuse(cg, label, f"artifact id {body.artifact_id} is already registered")

    # ---- 2. store the bytes exactly as received (no overwrite of other content) -------
    target = cg.settings.resolve_uri(body.subject.uri)
    if target.exists() and sha256_file(target) != sha256_file(model_path):
        raise _refuse(cg, label, f"a different file already exists at {body.subject.uri}")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.resolve() != model_path.resolve():
        shutil.copyfile(model_path, target)

    # ---- 3. store the envelope as received and index it ------------------------------
    env_path = write_envelope(raw, cg.settings.envelope_path(body.artifact_id))
    cg.repo.add_artifact(body, compute_manifest_digest(raw["payload"]), cg.settings.to_uri(env_path))

    # ---- 4. the decision: full verification (V0-V9) -----------------------------------
    report = cg.verifier.verify(body.artifact_id, context=context)
    accepted = report.status != Status.FAILED
    if accepted:
        log_event(cg.repo, INFO, EventType.EXTERNAL_IMPORTED,
                  f"Imported external model '{label}' from {body.signer.identity}: {report.status.value}",
                  artifact_id=body.artifact_id, details={"publisher": body.signer.identity,
                                                         "key_id": body.signer.key_id})
    else:
        log_event(cg.repo, CRITICAL, EventType.EXTERNAL_IMPORT_FAILED,
                  f"External model '{label}' failed verification ({', '.join(report.failed_checks())}); "
                  "quarantined: cannot be used as a parent or deployed",
                  artifact_id=body.artifact_id, details={"publisher": body.signer.identity,
                                                         "failed_checks": report.failed_checks()})
    return ImportResult(artifact_id=body.artifact_id, artifact_name=label, accepted=accepted,
                        report=report, stored_path=target)

"""Consume an artifact only after verification, without a time-of-check/time-of-use gap.

Naive pattern (vulnerable)::

    verify(model)          # checks the file on disk
    torch.load(path)       # ...but the file may have been swapped in between

Safe pattern used here: verify the chain, then read the bytes ONCE into memory,
hash THOSE bytes, compare with the signed digest, and hand the same bytes to the
consumer (training code, model loader). What is used is exactly what was checked.
"""

from __future__ import annotations

from dataclasses import dataclass

from chainguard.crypto.hashing import sha256_bytes
from chainguard.exceptions import UnverifiedArtifactError
from chainguard.manifest.builder import compute_manifest_digest, load_envelope_raw
from chainguard.manifest.models import ManifestBody
from chainguard.verification.results import Status, VerificationReport
from chainguard.verification.verifier import Verifier


@dataclass
class VerifiedArtifact:
    artifact_id: str
    body: ManifestBody
    data: bytes
    report: VerificationReport


def open_verified(verifier: Verifier, artifact_id: str, *, allow_warning: bool = True,
                  context: str = "pipeline") -> VerifiedArtifact:
    report = verifier.verify(artifact_id, context=context)
    if report.status == Status.FAILED or (report.status == Status.WARNING and not allow_warning):
        raise UnverifiedArtifactError(f"Refusing to consume {artifact_id}: {report.summary_line()}", report)
    raw = load_envelope_raw(verifier.settings.envelope_path(artifact_id))
    if compute_manifest_digest(raw["payload"]) != report.manifest_digest:
        raise UnverifiedArtifactError(f"{artifact_id} manifest changed after verification (TOCTOU)", report)
    body = ManifestBody.model_validate(raw["payload"])
    data = verifier.settings.resolve_uri(body.subject.uri).read_bytes()
    if sha256_bytes(data) != body.subject.sha256:
        # The file changed between verification and read: treat as an attack.
        raise UnverifiedArtifactError(f"{artifact_id} changed after verification (TOCTOU)", report)
    return VerifiedArtifact(artifact_id=artifact_id, body=body, data=data, report=report)

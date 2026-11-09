"""High-level registration (attestation) and revocation of artifacts.

register() implements the attestation sequence:

    hash file -> (dataset) Merkle tree + semantic checks -> resolve and VERIFY parents
    -> policy check -> build payload -> sign canonical bytes -> write envelope
    -> index in SQLite -> security event + metrics

A stage never attests on top of an unverified input: parents are verified first and
registration is refused if any parent FAILED.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chainguard.config import Settings
from chainguard.crypto.hashing import sha256_file
from chainguard.events import CRITICAL, INFO, EventType, log_event
from chainguard.exceptions import (
    ArtifactNotFoundError,
    PolicyViolationError,
    RegistrationError,
)
from chainguard.manifest.builder import (
    build_body,
    compute_manifest_digest,
    load_envelope_raw,
    sign_body,
    write_envelope,
)
from chainguard.manifest.models import ArtifactType, ManifestBody, MerkleInfo, ParentRef, SemanticCheck
from chainguard.metrics import record, timed
from chainguard.provenance.chain import build_environment
from chainguard.provenance.merkle import line_leaf_hashes, merkle_root_from_leaf_hashes, root_hex
from chainguard.provenance.policy import Policy
from chainguard.semantic.data_checks import run_dataset_checks
from chainguard.storage.repository import Repository
from chainguard.trust import TrustStore
from chainguard.verification.results import Status
from chainguard.verification.verifier import Verifier

MEDIA_TYPES = {
    ".csv": "text/csv",
    ".json": "application/json",
    ".safetensors": "application/safetensors",
    ".pt": "application/x-pytorch-pickle",
    ".pth": "application/x-pytorch-pickle",
    ".pkl": "application/x-pickle",
    ".bin": "application/octet-stream",
}


def guess_media_type(path: Path) -> str:
    return MEDIA_TYPES.get(path.suffix.lower(), "application/octet-stream")


@dataclass
class RegistrationResult:
    artifact_id: str
    artifact_name: str
    manifest_digest: str
    envelope_path: str
    sha256: str
    size_bytes: int
    merkle_root: str | None
    semantic_checks: list[SemanticCheck] = field(default_factory=list)
    timings_ms: dict[str, float] = field(default_factory=dict)

    def flagged(self) -> bool:
        return any(c.status == "flag" for c in self.semantic_checks)


class Registry:
    def __init__(self, settings: Settings, repo: Repository, policy: Policy, trust: TrustStore,
                 verifier: Verifier):
        self.settings = settings
        self.repo = repo
        self.policy = policy
        self.trust = trust
        self.verifier = verifier

    def register(
        self,
        file_path: str | Path,
        *,
        name: str,
        artifact_type: str,
        stage: str,
        role: str,
        version: str = "1.0.0",
        parents: Sequence[tuple[str, str]] = (),
        provenance: dict[str, Any] | None = None,
        run_semantic_checks: bool | None = None,
        reference_distribution: dict[int, float] | None = None,
        media_type: str | None = None,
        require_verified_parents: bool = True,
        enforce_policy: bool = True,
    ) -> RegistrationResult:
        """Attest one artifact. ``parents`` = [(parent_artifact_id, relation), ...].

        ``enforce_policy=False`` exists only so attack simulations can model a rogue
        pipeline that skips the registration-time policy check; the verifier still
        enforces the policy (check V8) independently.
        """
        path = Path(file_path)
        if not path.is_file():
            raise RegistrationError(f"File not found: {path}")
        uri = self.settings.to_uri(path)
        timings: dict[str, float] = {}

        # ---- 1. resolve and verify parents ----------------------------------------
        parent_refs: list[ParentRef] = []
        parent_types: list[tuple[str, str]] = []
        for parent_id, relation in parents:
            env_path = self.settings.envelope_path(parent_id)
            if not env_path.exists():
                raise RegistrationError(f"Parent {parent_id} has no signed envelope")
            if require_verified_parents:
                report = self.verifier.verify(parent_id, context="registration")
                if report.status == Status.FAILED:
                    log_event(self.repo, CRITICAL, EventType.REGISTRATION_REFUSED,
                              f"Refused to register '{name}': parent {report.summary_line()}",
                              details={"parent": parent_id, "failed_checks": report.failed_checks()})
                    raise RegistrationError(f"Parent {parent_id} failed verification: {report.summary_line()}")
            raw = load_envelope_raw(env_path)
            digest = compute_manifest_digest(raw["payload"])
            if require_verified_parents and digest != report.manifest_digest:
                raise RegistrationError(f"Parent {parent_id} changed during registration")
            pbody = ManifestBody.model_validate(raw["payload"])
            parent_refs.append(ParentRef(artifact_id=parent_id, manifest_digest=digest, relation=relation))
            parent_types.append((pbody.artifact_type, pbody.pipeline_stage))

        # ---- 2. policy --------------------------------------------------------------
        if enforce_policy:
            problems = self.policy.check_registration(artifact_type, stage, role, parent_types)
            if problems:
                log_event(self.repo, CRITICAL, EventType.REGISTRATION_REFUSED,
                          f"Policy refused '{name}': {'; '.join(problems)}", details={"problems": problems})
                raise PolicyViolationError("; ".join(problems))

        private_key, signer = self.trust.signing_key(role)

        # ---- 3. content hashing ---------------------------------------------------
        size = path.stat().st_size
        with timed() as t:
            sha = sha256_file(path)
        timings["hash"] = t.ms

        is_csv_dataset = artifact_type == ArtifactType.DATASET.value and path.suffix.lower() == ".csv"
        merkle: MerkleInfo | None = None
        leaves: list[bytes] = []
        data: bytes | None = None
        if is_csv_dataset:
            data = path.read_bytes()
            with timed() as t:
                leaves = line_leaf_hashes(data)
                merkle = MerkleInfo(root=root_hex(merkle_root_from_leaf_hashes(leaves)), leaf_count=len(leaves))
            timings["merkle"] = t.ms

        # ---- 4. semantic (content) checks, BEFORE signing --------------------------
        checks: list[SemanticCheck] = []
        do_checks = is_csv_dataset if run_semantic_checks is None else run_semantic_checks
        if do_checks and data is not None:
            with timed() as t:
                checks = run_dataset_checks(data, reference_distribution)
            timings["semantic"] = t.ms

        # ---- 5. manifest + signature ----------------------------------------------
        prov = dict(provenance or {})
        prov.setdefault("environment", build_environment())
        body = build_body(
            artifact_name=name, artifact_type=artifact_type, version=version, pipeline_stage=stage,
            subject_uri=uri, sha256=sha, size_bytes=size,
            media_type=media_type or guess_media_type(path),
            signer_identity=signer["identity"], signer_role=signer["role"], key_id=signer["key_id"],
            merkle=merkle, parents=parent_refs, provenance=prov, semantic_checks=checks,
        )
        with timed() as t:
            envelope = sign_body(body, private_key)
        timings["sign"] = t.ms

        env_path = write_envelope(envelope, self.settings.envelope_path(body.artifact_id))
        if leaves:
            self.settings.leaves_path(body.artifact_id).write_text(json.dumps([lf.hex() for lf in leaves]))
        self.repo.add_artifact(body, envelope.manifest_digest, self.settings.to_uri(env_path))

        # ---- 6. evidence -------------------------------------------------------------
        for op, ms in timings.items():
            record(self.repo, op, ms, artifact_id=body.artifact_id, size_bytes=size, stage=stage)
        record(self.repo, "register_total", sum(timings.values()), artifact_id=body.artifact_id,
               size_bytes=size, stage=stage)
        flagged = [c.name for c in checks if c.status == "flag"]
        log_event(self.repo, INFO, EventType.ARTIFACT_REGISTERED,
                  f"Registered {artifact_type} '{name}' v{version} ({stage}) signed by {signer['role']}"
                  + (f"; semantic flags: {', '.join(flagged)}" if flagged else ""),
                  artifact_id=body.artifact_id,
                  details={"manifest_digest": envelope.manifest_digest, "sha256": sha, "flags": flagged})

        return RegistrationResult(
            artifact_id=body.artifact_id, artifact_name=name, manifest_digest=envelope.manifest_digest,
            envelope_path=str(env_path), sha256=sha, size_bytes=size,
            merkle_root=merkle.root if merkle else None, semantic_checks=checks, timings_ms=timings,
        )

    def revoke(self, artifact_id: str, reason: str) -> bool:
        """Revoke an artifact: a signed record in the trust log (v0.4) plus the index flag."""
        if self.repo.get_artifact(artifact_id) is None:
            raise ArtifactNotFoundError(artifact_id)
        ok = self.trust.revoke_artifact(artifact_id, reason)
        if ok:
            log_event(self.repo, CRITICAL, EventType.ARTIFACT_REVOKED, f"Revoked: {reason}",
                      artifact_id=artifact_id, details={"reason": reason})
        return ok

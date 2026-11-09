"""The verifier: checks V0-V9 over an artifact and, recursively, its whole ancestry.

==== ===================================== ==========================================
ID   Check                                 Fails when
==== ===================================== ==========================================
V0   Envelope well-formed                  envelope missing, invalid JSON, schema error,
                                           or envelope stored under another artifact id
V1   File hash                             SHA-256 / size of the file != signed values
V2   Dataset Merkle root                   recomputed row root != signed root
                                           (reports WHICH rows changed)
V3   Ed25519 signature                     signature invalid over the canonical payload,
                                           or signing key unknown
V4   Signer trust                          key revoked, role/identity in the manifest !=
                                           role/identity registered for the key, or role
                                           not allowed to sign this stage
V5   Parent links                          a parent envelope is missing, or its recomputed
                                           manifest digest != digest embedded in the child
V6   Ancestor chain                        any ancestor FAILED (full recursive verification)
V7   Revocation                            artifact or any ancestor revoked, or artifact
                                           absent from the index (revocation unknowable)
V8   Policy                                wrong type for stage, missing/forbidden parent
                                           types, parent from a later stage
V9   Semantic checks                       a signed semantic check flagged the content,
                                           here or in an ancestor -> WARNING only
==== ===================================== ==========================================

Design principles
-----------------
* Every check runs and reports, so one call shows the complete picture.
* Nothing stored is trusted when it can be recomputed: file hashes, manifest
  digests and Merkle roots are always recalculated; the stored ``manifest_digest``
  field and ``last_status`` column are ignored.
* The DB is consulted only for the trust store (V3/V4) and revocation (V7).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from chainguard.config import Settings
from chainguard.crypto.canonical import canonical_json
from chainguard.crypto.hashing import sha256_file
from chainguard.crypto.signing import ALGORITHM, verify_bytes
from chainguard.events import CHECK_EVENT, CRITICAL, INFO, WARNING, EventType, log_event
from chainguard.exceptions import ConfigError, ManifestError
from chainguard.manifest.builder import compute_manifest_digest, load_envelope_raw, utc_now_iso
from chainguard.manifest.models import EXTERNAL_TYPES, Envelope, ManifestBody, ParentRef
from chainguard.metrics import record, timed
from chainguard.provenance.merkle import (
    diff_leaves,
    line_leaf_hashes,
    merkle_root_from_leaf_hashes,
    root_hex,
)
from chainguard.provenance.policy import Policy
from chainguard.storage.repository import Repository
from chainguard.verification.results import (
    AncestorSummary,
    CheckResult,
    Status,
    VerificationReport,
)

MAX_DEPTH = 32  # defensive bound on chain length


@dataclass
class _Run:
    """State shared across one top-level verification (memoisation + metrics)."""
    cache: dict[str, VerificationReport] = field(default_factory=dict)
    metrics: list[dict[str, Any]] = field(default_factory=list)


class Verifier:
    def __init__(self, settings: Settings, repo: Repository, policy: Policy):
        self.settings = settings
        self.repo = repo
        self.policy = policy

    # ------------------------------------------------------------------ public API
    def verify(self, artifact_id: str, file_path: str | Path | None = None, context: str = "cli",
               record_run: bool = True) -> VerificationReport:
        """Verify one artifact and its full ancestry.

        ``file_path`` lets a caller verify a candidate file (e.g. a model about to be
        deployed) against the signed manifest instead of the file at the signed URI.
        """
        run = _Run()
        with timed() as t:
            report = self._verify(artifact_id, Path(file_path) if file_path else None, run, ())
        report.duration_ms = round(t.ms, 3)
        report.verified_at = utc_now_iso()
        report.context = context
        if record_run:
            self._persist(report, run)
        return report

    # ------------------------------------------------------------------ internals
    def _verify(self, artifact_id: str, file_path: Path | None, run: _Run,
                stack: tuple[str, ...]) -> VerificationReport:
        if file_path is None and artifact_id in run.cache:
            return run.cache[artifact_id]

        checks: list[CheckResult] = []

        # ---- V0: envelope ---------------------------------------------------------
        raw, envelope, err = self._load(artifact_id)
        if envelope is None:
            checks.append(CheckResult.make("V0", "fail", err or "envelope unreadable"))
            report = VerificationReport(artifact_id=artifact_id, status=Status.FAILED, checks=checks)
            run.cache[artifact_id] = report
            return report
        body = envelope.payload
        payload_raw = raw["payload"]
        digest = compute_manifest_digest(payload_raw)
        checks.append(CheckResult.make("V0", "pass", "envelope parsed and schema-valid",
                                       schema_version=body.schema_version))

        # ---- V1 / V2: content integrity -------------------------------------------
        path, path_error = self._subject_path(body, file_path)
        checks.append(self._check_file_hash(body, path, path_error, run))
        checks.append(self._check_merkle(body, path))

        # ---- V3 / V4: signature and signer trust ----------------------------------
        signer = self.repo.get_signer(body.signer.key_id)
        checks.append(self._check_signature(envelope, payload_raw, signer, digest, run))
        checks.append(self._check_signer_trust(body, signer))

        # ---- V5: parent links -----------------------------------------------------
        v5, parents = self._check_parent_links(body)
        checks.append(v5)

        # ---- V6: recursive ancestry -----------------------------------------------
        ancestors: dict[str, AncestorSummary] = {}
        v6_problems: list[str] = []
        if len(stack) >= MAX_DEPTH:
            v6_problems.append(f"chain deeper than {MAX_DEPTH} levels")
        else:
            for ref, _pbody in parents:
                if ref.artifact_id == artifact_id or ref.artifact_id in stack:
                    v6_problems.append(f"provenance cycle through {ref.artifact_id}")
                    continue
                prep = self._verify(ref.artifact_id, None, run, (*stack, artifact_id))
                ancestors[prep.artifact_id] = self._summary(prep)
                for a in prep.ancestors:
                    ancestors.setdefault(a.artifact_id, a)
                if prep.status == Status.FAILED:
                    v6_problems.append(f"parent {prep.artifact_name or prep.artifact_id} FAILED "
                                       f"({', '.join(prep.failed_checks())})")
        failed_ancestors = [a.artifact_name or a.artifact_id for a in ancestors.values()
                            if a.status == Status.FAILED]
        if not body.parents:
            checks.append(CheckResult.make("V6", "skip", "root artifact: no ancestors"))
        elif v6_problems or failed_ancestors:
            checks.append(CheckResult.make("V6", "fail", "; ".join(v6_problems) or
                                           f"failed ancestors: {', '.join(failed_ancestors)}",
                                           failed_ancestors=failed_ancestors))
        else:
            checks.append(CheckResult.make("V6", "pass", f"{len(ancestors)} ancestor(s) verified",
                                           ancestor_count=len(ancestors)))

        # ---- V7: revocation -------------------------------------------------------
        v7, self_revoked = self._check_revocation(artifact_id, ancestors)
        checks.append(v7)

        # ---- V8: policy -----------------------------------------------------------
        problems = self.policy.check_stage(body.artifact_type, body.pipeline_stage)
        problems += self.policy.check_parents(
            body.artifact_type, body.pipeline_stage,
            [(pb.artifact_type, pb.pipeline_stage) for _, pb in parents])
        v8_ok = "type, stage and parent types allowed"
        if body.artifact_type in EXTERNAL_TYPES:
            v8_ok += f" (EXTERNAL model: provenance ends at publisher {body.signer.identity})"
        checks.append(CheckResult.make("V8", "fail" if problems else "pass",
                                       "; ".join(problems) or v8_ok, problems=problems))

        # ---- V9: semantic (content) evidence --------------------------------------
        checks.append(self._check_semantic(body, ancestors))

        report = VerificationReport(
            artifact_id=artifact_id,
            artifact_name=body.artifact_name,
            artifact_type=body.artifact_type,
            pipeline_stage=body.pipeline_stage,
            manifest_digest=digest,
            status=VerificationReport.derive_status(checks),
            checks=checks,
            ancestors=list(ancestors.values()),
            revoked=self_revoked,
            external_artifacts=([body.artifact_name] if body.artifact_type in EXTERNAL_TYPES else [])
            + [a.artifact_name or a.artifact_id for a in ancestors.values() if a.artifact_type in EXTERNAL_TYPES],
        )
        if file_path is None:
            run.cache[artifact_id] = report
        return report

    def _load(self, artifact_id: str) -> tuple[dict | None, Envelope | None, str | None]:
        path = self.settings.envelope_path(artifact_id)
        if not path.exists():
            return None, None, f"no signed envelope for {artifact_id}"
        try:
            raw = load_envelope_raw(path)
            envelope = Envelope.model_validate(raw)
        except (ManifestError, ValidationError) as exc:
            return None, None, f"malformed envelope: {str(exc).splitlines()[0]}"
        if envelope.payload.artifact_id != artifact_id:
            return None, None, (f"envelope stored as {artifact_id} declares artifact "
                                f"{envelope.payload.artifact_id} (envelope swap)")
        return raw, envelope, None

    def _subject_path(self, body: ManifestBody, override: Path | None) -> tuple[Path | None, str | None]:
        if override is not None:
            return override, None
        try:
            return self.settings.resolve_uri(body.subject.uri), None
        except ConfigError as exc:
            return None, str(exc)

    def _check_file_hash(self, body: ManifestBody, path: Path | None, path_error: str | None,
                         run: _Run) -> CheckResult:
        if path is None:
            return CheckResult.make("V1", "fail", path_error or "no artifact path")
        if not path.is_file():
            return CheckResult.make("V1", "fail", f"artifact file missing: {body.subject.uri}")
        size = path.stat().st_size
        with timed() as t:
            actual = sha256_file(path)
        run.metrics.append({"operation": "hash", "duration_ms": t.ms, "artifact_id": body.artifact_id,
                            "size_bytes": size})
        expected = body.subject.sha256
        if actual == expected and size == body.subject.size_bytes:
            return CheckResult.make("V1", "pass", "file bytes match the signed SHA-256", sha256=actual,
                                    size_bytes=size)
        return CheckResult.make("V1", "fail", "file content differs from the signed artifact",
                                expected_sha256=expected, actual_sha256=actual,
                                expected_size=body.subject.size_bytes, actual_size=size)

    def _check_merkle(self, body: ManifestBody, path: Path | None) -> CheckResult:
        merkle = body.subject.merkle
        if merkle is None:
            return CheckResult.make("V2", "skip", "no Merkle tree for this artifact type")
        if path is None or not path.is_file():
            return CheckResult.make("V2", "skip", "file missing (see V1)")
        leaves = line_leaf_hashes(path.read_bytes())
        current_root = root_hex(merkle_root_from_leaf_hashes(leaves))
        if current_root == merkle.root and len(leaves) == merkle.leaf_count:
            return CheckResult.make("V2", "pass", f"row Merkle root matches ({len(leaves)} leaves)",
                                    root=current_root)
        details: dict[str, Any] = {"expected_root": merkle.root, "actual_root": current_root}
        # Localise the change using the sidecar leaf list. The sidecar is only trusted
        # if it reproduces the SIGNED root, so an attacker cannot forge the diff.
        sidecar = self.settings.leaves_path(body.artifact_id)
        if sidecar.exists():
            try:
                signed_leaves = [bytes.fromhex(h) for h in json.loads(sidecar.read_text())]
                if root_hex(merkle_root_from_leaf_hashes(signed_leaves)) == merkle.root:
                    details["diff"] = diff_leaves(signed_leaves, leaves)
                    details["sidecar_authenticated"] = True
                else:
                    details["sidecar_authenticated"] = False
            except (ValueError, json.JSONDecodeError):
                details["sidecar_authenticated"] = False
        diff = details.get("diff")
        msg = "dataset rows changed after signing"
        if diff:
            msg += (f": {diff['changed_count']} line(s) modified, {diff['added_lines']} added, "
                    f"{diff['removed_lines']} removed")
        return CheckResult.make("V2", "fail", msg, **details)

    def _check_signature(self, envelope: Envelope, payload_raw: dict, signer: dict | None, digest: str,
                         run: _Run) -> CheckResult:
        key_id = envelope.payload.signer.key_id
        if signer is None:
            return CheckResult.make("V3", "fail", f"signing key {key_id} is not in the trust store",
                                    key_id=key_id)
        entries = [s for s in envelope.signatures if s.key_id == key_id]
        if not entries:
            return CheckResult.make("V3", "fail", f"no signature from declared key {key_id}", key_id=key_id)
        data = canonical_json(payload_raw)
        with timed() as t:
            ok = any(s.algorithm == ALGORITHM and verify_bytes(signer["public_key_b64"], data, s.sig)
                     for s in entries)
        run.metrics.append({"operation": "verify_signature", "duration_ms": t.ms,
                            "artifact_id": envelope.payload.artifact_id, "size_bytes": len(data)})
        stored_ok = envelope.manifest_digest == digest
        if ok:
            return CheckResult.make("V3", "pass", f"valid Ed25519 signature by {key_id}",
                                    key_id=key_id, manifest_digest=digest, stored_digest_consistent=stored_ok)
        return CheckResult.make("V3", "fail", "signature does not match the manifest payload",
                                key_id=key_id, manifest_digest=digest, stored_digest_consistent=stored_ok)

    def _check_signer_trust(self, body: ManifestBody, signer: dict | None) -> CheckResult:
        if signer is None:
            return CheckResult.make("V4", "fail", "unknown signer key", key_id=body.signer.key_id)
        problems: list[str] = []
        if signer.get("revoked_at"):
            problems.append(f"key revoked at {signer['revoked_at']} ({signer.get('revoked_reason')})")
        if signer["role"] != body.signer.role:
            problems.append(f"manifest claims role '{body.signer.role}' but key is registered "
                            f"for '{signer['role']}'")
        if signer["identity"] != body.signer.identity:
            problems.append(f"manifest claims identity '{body.signer.identity}' but key belongs to "
                            f"'{signer['identity']}'")
        problems += self.policy.check_signer(signer["role"], body.pipeline_stage)
        if problems:
            return CheckResult.make("V4", "fail", "; ".join(problems), problems=problems)
        return CheckResult.make("V4", "pass", f"{signer['identity']} ({signer['role']}) may sign "
                                f"{body.pipeline_stage}", identity=signer["identity"], role=signer["role"])

    def _check_parent_links(self, body: ManifestBody) -> tuple[CheckResult, list[tuple[ParentRef, ManifestBody]]]:
        parents: list[tuple[ParentRef, ManifestBody]] = []
        problems: list[str] = []
        links: list[dict[str, Any]] = []
        for ref in body.parents:
            praw, penv, err = self._load(ref.artifact_id)
            if penv is None:
                problems.append(f"parent {ref.artifact_id} ({ref.relation}): {err}")
                links.append({"artifact_id": ref.artifact_id, "relation": ref.relation, "ok": False})
                continue
            actual = compute_manifest_digest(praw["payload"])
            ok = actual == ref.manifest_digest
            if not ok:
                problems.append(f"parent {penv.payload.artifact_name} ({ref.relation}) manifest digest changed: "
                                f"expected {ref.manifest_digest[:19]}..., found {actual[:19]}...")
            links.append({"artifact_id": ref.artifact_id, "relation": ref.relation, "ok": ok,
                          "expected_digest": ref.manifest_digest, "actual_digest": actual})
            parents.append((ref, penv.payload))
        if not body.parents:
            return CheckResult.make("V5", "pass", "no parents declared (root artifact)", links=[]), parents
        if problems:
            return CheckResult.make("V5", "fail", "; ".join(problems), links=links), parents
        return CheckResult.make("V5", "pass", f"{len(links)} parent link(s) match", links=links), parents

    def _check_revocation(self, artifact_id: str, ancestors: dict[str, AncestorSummary]
                          ) -> tuple[CheckResult, bool]:
        row = self.repo.get_artifact(artifact_id)
        problems: list[str] = []
        self_revoked = False
        if row is None:
            # Deleting the index row must not be a way to escape revocation.
            problems.append("artifact not in registry index: revocation state cannot be confirmed")
        elif row["revoked"]:
            self_revoked = True
            problems.append(f"artifact revoked: {row.get('revoked_reason')}")
        revoked_anc = [a.artifact_name or a.artifact_id for a in ancestors.values() if a.revoked]
        if revoked_anc:
            problems.append(f"revoked ancestor(s): {', '.join(revoked_anc)}")
        if problems:
            return CheckResult.make("V7", "fail", "; ".join(problems), revoked_ancestors=revoked_anc), self_revoked
        return CheckResult.make("V7", "pass", "artifact and ancestors not revoked"), self_revoked

    def _check_semantic(self, body: ManifestBody, ancestors: dict[str, AncestorSummary]) -> CheckResult:
        flags = [c for c in body.semantic_checks if c.status == "flag"]
        inherited = [a.artifact_name or a.artifact_id for a in ancestors.values() if "V9" in a.warned_checks]
        if flags or inherited:
            parts = [f"{c.name}: {c.summary}" for c in flags]
            if inherited:
                parts.append(f"flagged ancestor(s): {', '.join(inherited)}")
            return CheckResult.make("V9", "warn", "integrity intact but content flagged - " + "; ".join(parts),
                                    flags=[c.model_dump() for c in flags], inherited_from=inherited)
        if body.semantic_checks:
            return CheckResult.make("V9", "pass", f"{len(body.semantic_checks)} content check(s) passed "
                                    "(heuristic evidence, not proof)",
                                    checks=[c.name for c in body.semantic_checks])
        return CheckResult.make("V9", "skip", "no content checks recorded for this artifact: integrity-only guarantee")

    @staticmethod
    def _summary(report: VerificationReport) -> AncestorSummary:
        return AncestorSummary(
            artifact_id=report.artifact_id, artifact_name=report.artifact_name,
            artifact_type=report.artifact_type, manifest_digest=report.manifest_digest,
            status=report.status, failed_checks=report.failed_checks(),
            warned_checks=report.warned_checks(), revoked=report.revoked)

    def _persist(self, report: VerificationReport, run: _Run) -> None:
        checks = [c.model_dump() for c in report.checks]
        self.repo.add_run(report.artifact_id, report.context, report.status.value, checks, report.duration_ms)
        self.repo.set_status(report.artifact_id, report.status.value)
        for m in run.metrics:
            record(self.repo, m["operation"], m["duration_ms"], artifact_id=m["artifact_id"],
                   size_bytes=m["size_bytes"], context=report.context, chain_root=report.artifact_id)
        record(self.repo, "verify_full", report.duration_ms, artifact_id=report.artifact_id,
               context=report.context, status=report.status.value, chain_length=len(report.ancestors) + 1)

        name = report.artifact_name or report.artifact_id
        if report.status == Status.FAILED:
            for c in report.checks:
                if c.outcome == "fail":
                    log_event(self.repo, CRITICAL, CHECK_EVENT[c.check_id], f"{name}: {c.message}",
                              artifact_id=report.artifact_id,
                              details={"check": c.check_id, "context": report.context})
        elif report.status == Status.WARNING:
            log_event(self.repo, WARNING, EventType.SEMANTIC_FLAG, f"{name}: {report.check('V9').message}",
                      artifact_id=report.artifact_id, details={"context": report.context})
        else:
            log_event(self.repo, INFO, EventType.VERIFICATION_PASSED,
                      f"{name} verified with {len(report.ancestors)} ancestor(s)",
                      artifact_id=report.artifact_id, details={"context": report.context})

    # ------------------------------------------------------------------ helpers
    def chain_digests(self, report: VerificationReport) -> list[str]:
        """Manifest digests of an artifact and all its ancestors (for the release root)."""
        digests = [report.manifest_digest] + [a.manifest_digest for a in report.ancestors]
        return [d for d in digests if d]

"""Result types for verification.

The overall status is DERIVED from individual check outcomes, never set by hand:

* FAILED   - at least one check failed (cryptographic integrity or policy broken)
* WARNING  - integrity intact, but a semantic check flagged the content
             (here or in an ancestor)
* VERIFIED - every check passed. This means "exactly what trusted signers attested,
             through an intact chain". It does NOT mean "the model is safe".
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Status(str, Enum):
    VERIFIED = "VERIFIED"
    WARNING = "WARNING"
    FAILED = "FAILED"


Outcome = Literal["pass", "fail", "warn", "skip"]

CHECK_NAMES: dict[str, str] = {
    "V0": "Envelope well-formed",
    "V1": "File hash (SHA-256)",
    "V2": "Dataset Merkle root",
    "V3": "Ed25519 signature",
    "V4": "Signer trusted for role and stage",
    "V5": "Parent links (manifest digests)",
    "V6": "Ancestor chain verified",
    "V7": "Revocation (artifact and ancestors)",
    "V8": "Supply-chain policy",
    "V9": "Semantic checks (content)",
}


class CheckResult(BaseModel):
    check_id: str
    name: str
    outcome: Outcome
    message: str
    details: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def make(cls, check_id: str, outcome: Outcome, message: str, **details: Any) -> CheckResult:
        return cls(check_id=check_id, name=CHECK_NAMES[check_id], outcome=outcome,
                   message=message, details=details)


class AncestorSummary(BaseModel):
    artifact_id: str
    artifact_name: str | None = None
    artifact_type: str | None = None
    manifest_digest: str | None = None
    status: Status
    failed_checks: list[str] = Field(default_factory=list)
    warned_checks: list[str] = Field(default_factory=list)
    revoked: bool = False


class VerificationReport(BaseModel):
    artifact_id: str
    artifact_name: str | None = None
    artifact_type: str | None = None
    pipeline_stage: str | None = None
    manifest_digest: str | None = None
    status: Status
    checks: list[CheckResult]
    ancestors: list[AncestorSummary] = Field(default_factory=list)
    revoked: bool = False
    # v0.3: names of externally published artifacts in this chain (the artifact itself
    # or an ancestor). Their provenance stops at the publisher's signature: VERIFIED
    # proves origin and integrity, not how (or on what data) they were trained.
    external_artifacts: list[str] = Field(default_factory=list)
    # v0.4: the signed trust log this verdict was computed against. ``trust_log_ok`` is
    # False when the log was missing, truncated or tampered with (V3/V4/V7 then fail).
    trust_log_ok: bool = True
    trust_log_seq: int = 0
    trust_log_head: str | None = None
    duration_ms: float = 0.0
    verified_at: str = ""
    context: str = "cli"

    @staticmethod
    def derive_status(checks: list[CheckResult]) -> Status:
        if any(c.outcome == "fail" for c in checks):
            return Status.FAILED
        if any(c.outcome == "warn" for c in checks):
            return Status.WARNING
        return Status.VERIFIED

    def failed_checks(self) -> list[str]:
        return [c.check_id for c in self.checks if c.outcome == "fail"]

    def warned_checks(self) -> list[str]:
        return [c.check_id for c in self.checks if c.outcome == "warn"]

    def check(self, check_id: str) -> CheckResult | None:
        return next((c for c in self.checks if c.check_id == check_id), None)

    def summary_line(self) -> str:
        bad = self.failed_checks() or self.warned_checks()
        suffix = f" ({', '.join(bad)})" if bad else ""
        return f"{self.status.value}{suffix} {self.artifact_name or self.artifact_id}"

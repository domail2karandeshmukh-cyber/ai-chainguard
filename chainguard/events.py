"""Security event logging.

Events are written both to the SQLite index (for the dashboard) and to the Python
logger (for container logs / SIEM forwarding).
"""

from __future__ import annotations

import logging
from typing import Any

from chainguard.storage.repository import Repository

logger = logging.getLogger("chainguard.events")

INFO, WARNING, CRITICAL = "info", "warning", "critical"


class EventType:
    KEY_CREATED = "KEY_CREATED"
    KEY_REVOKED = "KEY_REVOKED"
    ARTIFACT_REGISTERED = "ARTIFACT_REGISTERED"
    REGISTRATION_REFUSED = "REGISTRATION_REFUSED"
    ARTIFACT_REVOKED = "ARTIFACT_REVOKED"
    VERIFICATION_PASSED = "VERIFICATION_PASSED"
    MANIFEST_INVALID = "MANIFEST_INVALID"
    HASH_MISMATCH = "HASH_MISMATCH"
    MERKLE_MISMATCH = "MERKLE_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    UNTRUSTED_SIGNER = "UNTRUSTED_SIGNER"
    PROVENANCE_BROKEN = "PROVENANCE_BROKEN"
    ANCESTOR_FAILED = "ANCESTOR_FAILED"
    REVOKED_IN_CHAIN = "REVOKED_IN_CHAIN"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    SEMANTIC_FLAG = "SEMANTIC_FLAG"
    DEPLOYMENT_APPROVED = "DEPLOYMENT_APPROVED"
    DEPLOYMENT_BLOCKED = "DEPLOYMENT_BLOCKED"
    DEMO_TAMPER = "DEMO_TAMPER"
    EXTERNAL_IMPORTED = "EXTERNAL_IMPORTED"            # v0.3: external model accepted
    EXTERNAL_IMPORT_FAILED = "EXTERNAL_IMPORT_FAILED"  # v0.3: imported but failed verification
    EXTERNAL_IMPORT_REFUSED = "EXTERNAL_IMPORT_REFUSED"  # v0.3: e.g. unsigned, not even stored
    TRUST_LOG_INITIALISED = "TRUST_LOG_INITIALISED"    # v0.4: root key pinned, genesis record written
    TRUST_LOG_INVALID = "TRUST_LOG_INVALID"            # v0.4: log missing, truncated or tampered -> fail closed
    INDEX_TAMPERING = "INDEX_TAMPERING"                # v0.4: SQLite index disagrees with the signed log


# Event emitted when a given verification check fails (see verification/verifier.py).
CHECK_EVENT = {
    "V0": EventType.MANIFEST_INVALID,
    "V1": EventType.HASH_MISMATCH,
    "V2": EventType.MERKLE_MISMATCH,
    "V3": EventType.SIGNATURE_INVALID,
    "V4": EventType.UNTRUSTED_SIGNER,
    "V5": EventType.PROVENANCE_BROKEN,
    "V6": EventType.ANCESTOR_FAILED,
    "V7": EventType.REVOKED_IN_CHAIN,
    "V8": EventType.POLICY_VIOLATION,
    "V9": EventType.SEMANTIC_FLAG,
}

_LEVEL = {INFO: logging.INFO, WARNING: logging.WARNING, CRITICAL: logging.CRITICAL}


def log_event(repo: Repository, severity: str, event_type: str, message: str,
              artifact_id: str | None = None, details: dict[str, Any] | None = None) -> None:
    logger.log(_LEVEL.get(severity, logging.INFO), "%s artifact=%s %s", event_type, artifact_id, message)
    repo.add_event(severity, event_type, message, artifact_id=artifact_id, details=details)

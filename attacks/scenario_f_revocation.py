"""Scenario F - Experiment 5: artifact and key revocation, and attempts to bypass it.

Each variant starts from a fresh copy of the clean, fully attested chain.

========  ======================================================  ==========  ======================
ID        Action                                                  Expected    Why
========  ======================================================  ==========  ======================
E5-0      control: verify the final model, gateway deploys it     VERIFIED    nothing revoked
E5-A1     revoke the BASE model; verify the fine-tuned model      FAILED      V7 revoked ancestor
E5-A2     ...then ask the gateway to deploy the fine-tuned model  FAILED      gateway BLOCKS
E5-B1     revoke the training_pipeline KEY; verify final model    FAILED      V4 (+V6 via the base)
E5-B2     ...verify a dataset signed by another role              VERIFIED    blast radius limited to
                                                                              what that key signed
E5-C1     bypass: delete the revoked artifact's index row         FAILED      V7 "revocation state
                                                                              cannot be confirmed"
E5-C2     bypass: delete the revoked KEY from the index           FAILED      V4: the signed log still
                                                                              says revoked (+index row
                                                                              missing = tampering)
E5-C3     bypass: overwrite the cached last_status = VERIFIED     FAILED      verifier never reads
                                                                              the cached status
E5-C4     bypass: flip the revoked flag back to 0 in SQLite       FAILED      v0.4: revocation lives
          (the v0.3 LIMITATION)                                               in the SIGNED log; the
                                                                              index disagreement is
                                                                              reported as tampering
E5-C5     bypass: insert the attacker's own key into the index    FAILED      V3/V4: key never
          and sign a substituted model with it                                trusted in the signed
                                                                              log (unauthorised
                                                                              insertion)
E5-C6     bypass: truncate the trust log (drop the revocation)    FAILED      pinned head != log head
                                                                              -> rollback detected,
                                                                              fail closed
E5-C7     bypass: edit a log record (revoke -> re-trust)          FAILED      root signature invalid
                                                                              -> fail closed
E5-C8     bypass: delete the trust log file                       FAILED      log missing -> fail
                                                                              closed
========  ======================================================  ==========  ======================

What remains trusted: the keys directory (root private key and the pin
``keys/trust_root.json``), the policy and the verifier. An attacker who controls
those controls everything, as the threat model states. Revocation is still local to
one trust log; publishing the records to a shared transparency log is future work.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from attacks.common import (
    Variant,
    edit_envelope,
    fresh_chain,
    from_report,
    observe,
    subject_path,
    write_result,
)
from chainguard.crypto.canonical import canonical_json
from chainguard.crypto.keys import compute_key_id, generate_private_key, public_key_b64
from chainguard.crypto.signing import sign_bytes
from deployment.gateway import DeploymentGateway

TITLE = "Revocation (Experiment 5)"
DEMONSTRATES = ("Revoking an artifact or a signing key invalidates it and everything derived from it, and "
                "the gateway blocks deployment. Since v0.4 trust and revocation live in a signed, pinned, "
                "append-only log: editing the SQLite index (un-revoke, rogue key) and tampering with the log "
                "itself (truncate, edit, delete) are all detected and fail closed.")


def _sql(cg, statement: str, params: tuple = ()) -> None:
    """Direct write to the SQLite index, as an attacker with file access would do."""
    with sqlite3.connect(cg.settings.db_path) as conn:
        conn.execute(statement, params)


def _log_lines(cg) -> list[bytes]:
    return [ln for ln in cg.settings.trust_log_path.read_bytes().split(b"\n") if ln.strip()]


def _write_log(cg, lines: list[bytes]) -> None:
    cg.settings.trust_log_path.write_bytes(b"\n".join(lines) + b"\n")


def _rogue_key_resigns(cg, artifact_id: str) -> str:
    """E5-C5: the attacker generates a key, writes it into the ``signers`` table with the
    training_pipeline role (as if trusted), substitutes the model file and re-signs the
    manifest with that key. Every stored artefact is self-consistent; only the signed
    trust log knows the key was never authorised."""
    rogue = generate_private_key()
    kid = compute_key_id(rogue.public_key())
    _sql(cg, "INSERT INTO signers (key_id, identity, role, public_key_b64, created_at) VALUES (?,?,?,?,?)",
         (kid, f"training_pipeline@{cg.settings.identity_domain}", "training_pipeline",
          public_key_b64(rogue.public_key()), "2026-11-09T00:00:00Z"))
    path = subject_path(cg, artifact_id)
    data = bytearray(path.read_bytes())
    data[-1] ^= 0x01
    path.write_bytes(bytes(data))

    def mutate(raw: dict[str, Any]) -> None:
        from chainguard.crypto.hashing import sha256_file
        raw["payload"]["subject"]["sha256"] = sha256_file(path)
        raw["payload"]["signer"]["key_id"] = kid
        raw["signatures"] = [{"key_id": kid, "algorithm": "Ed25519",
                              "sig": sign_bytes(rogue, canonical_json(raw["payload"]))}]
    edit_envelope(cg, artifact_id, mutate)
    _sql(cg, "UPDATE artifacts SET signer_key_id = ? WHERE artifact_id = ?", (kid, artifact_id))
    return kid


def run(out_dir: Path | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    variants: list[Variant] = []

    # ---- E5-0 control -----------------------------------------------------------------
    cg, ids = fresh_chain()
    d0 = DeploymentGateway(cg).deploy(ids["final_model"])
    variants.append(from_report(d0.report, "E5-0", "Control: nothing revoked, gateway deploys", "none",
                                "VERIFIED", "final model", deployed=d0.deployed,
                                trust_log_seq=d0.report.trust_log_seq))

    # ---- E5-A artifact revocation ------------------------------------------------------
    cg, ids = fresh_chain()
    t0 = time.perf_counter()
    cg.registry.revoke(ids["base_model"], "base model withdrawn (simulated incident)")
    variants.append(observe(cg, "F", "E5-A1", "Revoke the base model -> descendant fails",
                            "base model revoked; fine-tuned model verified", ids["final_model"], "FAILED",
                            "final model"))
    dA = DeploymentGateway(cg).deploy(ids["final_model"])
    variants.append(from_report(dA.report, "E5-A2", "Revoked ancestor -> deployment BLOCKED",
                                "gateway asked to deploy the fine-tuned model", "FAILED", "final model",
                                deployed=dA.deployed, gateway_reason=dA.reason,
                                revocation_to_block_ms=round((time.perf_counter() - t0) * 1000, 3)))

    # ---- E5-B key revocation -----------------------------------------------------------
    cg, ids = fresh_chain()
    key_id = cg.repo.active_signer_for_role("training_pipeline")["key_id"]
    cg.trust.revoke_key(key_id, "training key compromised (simulated)")
    variants.append(observe(cg, "F", "E5-B1", "Revoke the training_pipeline key -> its models fail",
                            f"key {key_id} revoked", ids["final_model"], "FAILED", "final model"))
    variants.append(observe(cg, "F", "E5-B2", "Dataset signed by another role still verifies",
                            f"same revocation of {key_id}; dataset signed by data_steward",
                            ids["train_dataset"], "VERIFIED", "train dataset"))

    # ---- E5-C bypass attempts against the INDEX ----------------------------------------
    cg, ids = fresh_chain()
    cg.registry.revoke(ids["final_model"], "withdrawn")
    _sql(cg, "DELETE FROM artifact_parents WHERE child_id = ? OR parent_id = ?",
         (ids["final_model"], ids["final_model"]))
    _sql(cg, "DELETE FROM artifacts WHERE artifact_id = ?", (ids["final_model"],))
    variants.append(observe(cg, "F", "E5-C1", "Bypass: delete the revoked artifact's index row",
                            "revoked final model's row removed from the SQLite index", ids["final_model"],
                            "FAILED", "final model"))

    cg, ids = fresh_chain()
    key_id = cg.repo.active_signer_for_role("training_pipeline")["key_id"]
    cg.trust.revoke_key(key_id, "training key compromised (simulated)")
    _sql(cg, "DELETE FROM signers WHERE key_id = ?", (key_id,))
    variants.append(observe(cg, "F", "E5-C2", "Bypass: delete the revoked key from the index",
                            f"revoked key {key_id} row removed from the signers table", ids["final_model"],
                            "FAILED", "final model"))

    cg, ids = fresh_chain()
    cg.registry.revoke(ids["base_model"], "withdrawn")
    _sql(cg, "UPDATE artifacts SET last_status = 'VERIFIED'")
    variants.append(observe(cg, "F", "E5-C3", "Bypass: overwrite cached status with VERIFIED",
                            "last_status column forced to VERIFIED for every artifact", ids["final_model"],
                            "FAILED", "final model"))

    cg, ids = fresh_chain()
    cg.registry.revoke(ids["base_model"], "withdrawn")
    _sql(cg, "UPDATE artifacts SET revoked = 0, revoked_reason = NULL, revoked_at = NULL WHERE artifact_id = ?",
         (ids["base_model"],))
    variants.append(observe(cg, "F", "E5-C4", "Bypass: un-revoke by editing the index (v0.3 limitation)",
                            "revoked flag set back to 0 directly in SQLite", ids["final_model"], "FAILED",
                            "final model", closed_in="v0.4: revocation is read from the signed trust log; "
                            "the index disagreement is logged as INDEX_TAMPERING"))

    cg, ids = fresh_chain()
    kid = _rogue_key_resigns(cg, ids["final_model"])
    variants.append(observe(cg, "F", "E5-C5", "Bypass: rogue key inserted into the index signs a model",
                            f"attacker key {kid} written into the signers table as training_pipeline; final model "
                            "substituted and re-signed with it", ids["final_model"], "FAILED", "final model"))

    # ---- E5-C bypass attempts against the SIGNED LOG -----------------------------------
    cg, ids = fresh_chain()
    cg.registry.revoke(ids["base_model"], "withdrawn")
    _sql(cg, "UPDATE artifacts SET revoked = 0, revoked_reason = NULL, revoked_at = NULL WHERE artifact_id = ?",
         (ids["base_model"],))
    lines = _log_lines(cg)
    _write_log(cg, lines[:-1])          # drop the revocation record = roll the log back
    variants.append(observe(cg, "F", "E5-C6", "Bypass: truncate the trust log (rollback)",
                            "last record (the revocation) removed from trust_log.jsonl; index flag cleared",
                            ids["final_model"], "FAILED", "final model", log_records_before=len(lines)))

    cg, ids = fresh_chain()
    cg.registry.revoke(ids["base_model"], "withdrawn")
    lines = _log_lines(cg)
    rec = json.loads(lines[-1])
    rec["entry"]["action"] = "trust_key"   # turn the revocation into something harmless, keep the signature
    rec["entry"]["subject"] = {"key_id": "ed25519:0000000000000000", "identity": "x@y", "role": "data_steward",
                               "public_key_b64": public_key_b64(generate_private_key().public_key())}
    lines[-1] = canonical_json(rec)
    _write_log(cg, lines)
    variants.append(observe(cg, "F", "E5-C7", "Bypass: edit a trust-log record in place",
                            "revoke_artifact record rewritten as trust_key without the root key",
                            ids["final_model"], "FAILED", "final model"))

    cg, ids = fresh_chain()
    cg.registry.revoke(ids["base_model"], "withdrawn")
    _sql(cg, "UPDATE artifacts SET revoked = 0, revoked_reason = NULL, revoked_at = NULL WHERE artifact_id = ?",
         (ids["base_model"],))
    os.remove(cg.settings.trust_log_path)
    variants.append(observe(cg, "F", "E5-C8", "Bypass: delete the trust log",
                            "trust_log.jsonl deleted; index flag cleared", ids["final_model"], "FAILED",
                            "final model"))

    extra = {"interpretation": (
        "Artifact and key revocation propagate to every descendant and block deployment. Every bypass that "
        "edits the SQLite index (delete rows, cached status, un-revoke, rogue key) fails because the verifier "
        "reads trust and revocation from the signed, pinned trust log, and every attack on the log itself "
        "(truncation, in-place edit, deletion) fails closed because the log must replay exactly to the pinned "
        "head under the root key's signatures. The v0.3 limitation E5-C4 is closed.")}
    return write_result("F", TITLE, DEMONSTRATES, variants, started, out_dir, extra=extra)


if __name__ == "__main__":
    print(json.dumps(run(), indent=2)[:6000])

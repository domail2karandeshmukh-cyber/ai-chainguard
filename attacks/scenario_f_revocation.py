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
E5-C2     bypass: delete the revoked KEY from the trust store     FAILED      V3/V4 unknown key
E5-C3     bypass: overwrite the cached last_status = VERIFIED     FAILED      verifier never reads
                                                                              the cached status
E5-C4     LIMITATION: flip the revoked flag back to 0 in SQLite   VERIFIED    revocation state lives
                                                                              in the TRUSTED index;
                                                                              write access to it =
                                                                              un-revocation
========  ======================================================  ==========  ======================

E5-C4 is reported honestly as a limitation of the current architecture (the trust store
and revocation list are trusted components, see the threat model). Production fix: a
signed, append-only revocation list / transparency log that the verifier checks
independently of the mutable index.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

from attacks.common import Variant, fresh_chain, from_report, observe, write_result
from deployment.gateway import DeploymentGateway

TITLE = "Revocation (Experiment 5)"
DEMONSTRATES = ("Revoking an artifact or a signing key invalidates it and everything derived from it, and "
                "the gateway blocks deployment; deleting index rows does not undo a revocation. Editing "
                "the trusted index itself is a documented limitation.")


def _sql(cg, statement: str, params: tuple = ()) -> None:
    """Direct write to the SQLite index, as an attacker with file access would do."""
    with sqlite3.connect(cg.settings.db_path) as conn:
        conn.execute(statement, params)


def run(out_dir: Path | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    variants: list[Variant] = []

    # ---- E5-0 control -----------------------------------------------------------------
    cg, ids = fresh_chain()
    d0 = DeploymentGateway(cg).deploy(ids["final_model"])
    variants.append(from_report(d0.report, "E5-0", "Control: nothing revoked, gateway deploys", "none",
                                "VERIFIED", "final model", deployed=d0.deployed))

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

    # ---- E5-C bypass attempts ----------------------------------------------------------
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
    variants.append(observe(cg, "F", "E5-C2", "Bypass: delete the revoked key from the trust store",
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
    v = observe(cg, "F", "E5-C4", "LIMITATION: un-revoke by editing the trusted index",
                "revoked flag set back to 0 directly in SQLite", ids["final_model"], "VERIFIED", "final model",
                limitation=("revocation state is stored in the trusted SQLite index; an attacker with write "
                            "access to it can undo a revocation. Fix: signed append-only revocation list."))
    variants.append(v)

    extra = {"interpretation": (
        "Artifact and key revocation propagate to every descendant and block deployment. Deleting the "
        "revoked artifact or key from the index fails closed, and the cached status is never trusted. "
        "E5-C4 shows the remaining gap: the revocation flag itself is only as trustworthy as the index.")}
    return write_result("F", TITLE, DEMONSTRATES, variants, started, out_dir, extra=extra)


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2)[:6000])

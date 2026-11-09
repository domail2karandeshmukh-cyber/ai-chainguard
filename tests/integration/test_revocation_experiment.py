"""Experiment 5 (v0.3): revocation propagation, gateway enforcement, bypass attempts."""

from __future__ import annotations

import sqlite3

from chainguard.verification.results import Status
from deployment.gateway import DeploymentGateway


def sql(cg, statement, params=()):
    with sqlite3.connect(cg.settings.db_path) as conn:
        conn.execute(statement, params)


def failed(report):
    return set(report.failed_checks())


def test_revoked_ancestor_blocks_deployment(cg, chain):
    cg.registry.revoke(chain["base"], "withdrawn")
    d = DeploymentGateway(cg).deploy(chain["final"])
    assert not d.deployed and d.status == "FAILED" and "V7" in d.report.failed_checks()
    assert any(e["event_type"] == "DEPLOYMENT_BLOCKED" for e in cg.repo.list_events())


def test_key_revocation_blast_radius_is_limited_to_that_key(cg, chain):
    cg.trust.revoke_key(cg.repo.active_signer_for_role("training_pipeline")["key_id"], "compromised")
    assert cg.verifier.verify(chain["final"]).status == Status.FAILED
    assert cg.verifier.verify(chain["dataset"]).status == Status.VERIFIED   # signed by data_steward


def test_bypass_delete_revoked_key_from_trust_store_fails_closed(cg, chain):
    key_id = cg.repo.active_signer_for_role("training_pipeline")["key_id"]
    cg.trust.revoke_key(key_id, "compromised")
    sql(cg, "DELETE FROM signers WHERE key_id = ?", (key_id,))
    r = cg.verifier.verify(chain["final"])
    assert r.status == Status.FAILED and {"V3", "V4"} <= failed(r)


def test_bypass_cached_status_is_never_trusted(cg, chain):
    cg.registry.revoke(chain["base"], "withdrawn")
    sql(cg, "UPDATE artifacts SET last_status = 'VERIFIED'")
    assert cg.verifier.verify(chain["final"]).status == Status.FAILED


def test_limitation_editing_the_trusted_index_undoes_revocation(cg, chain):
    """Documents a KNOWN LIMITATION (Experiment 5, E5-C4): revocation state lives in the
    trusted SQLite index. If this test starts failing because a signed revocation list was
    added, update the experiment and the report accordingly."""
    cg.registry.revoke(chain["base"], "withdrawn")
    assert cg.verifier.verify(chain["final"]).status == Status.FAILED
    sql(cg, "UPDATE artifacts SET revoked = 0 WHERE artifact_id = ?", (chain["base"],))
    assert cg.verifier.verify(chain["final"]).status == Status.VERIFIED

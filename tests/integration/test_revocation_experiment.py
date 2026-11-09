"""Experiment 5: revocation propagation, gateway enforcement, bypass attempts.

v0.4: trust and revocation are read from the signed trust log, so the former
limitation E5-C4 (un-revoke by editing the index) is now a detected attack, and
attacks on the log itself (truncate, edit, delete) fail closed."""

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


def test_bypass_delete_revoked_key_from_index_fails_closed(cg, chain):
    key_id = cg.repo.active_signer_for_role("training_pipeline")["key_id"]
    cg.trust.revoke_key(key_id, "compromised")
    sql(cg, "DELETE FROM signers WHERE key_id = ?", (key_id,))
    r = cg.verifier.verify(chain["final"])
    # The signed log still knows the key (and its revocation): V4 fails, and the missing
    # index row is reported as tampering.
    assert r.status == Status.FAILED and "V4" in failed(r)
    assert "index tampering" in r.check("V4").message
    assert any(e["event_type"] == "INDEX_TAMPERING" for e in cg.repo.list_events())


def test_bypass_cached_status_is_never_trusted(cg, chain):
    cg.registry.revoke(chain["base"], "withdrawn")
    sql(cg, "UPDATE artifacts SET last_status = 'VERIFIED'")
    assert cg.verifier.verify(chain["final"]).status == Status.FAILED


def test_editing_the_index_no_longer_undoes_revocation(cg, chain):
    """E5-C4, a documented LIMITATION until v0.3: revocation state lived in the trusted
    SQLite index. Since v0.4 it lives in the signed trust log; the cleared flag is
    detected as index tampering."""
    cg.registry.revoke(chain["base"], "withdrawn")
    assert cg.verifier.verify(chain["final"]).status == Status.FAILED
    sql(cg, "UPDATE artifacts SET revoked = 0 WHERE artifact_id = ?", (chain["base"],))
    r = cg.verifier.verify(chain["final"])
    assert r.status == Status.FAILED and "V6" in failed(r)
    base = cg.verifier.verify(chain["base"])
    assert "V7" in failed(base) and base.check("V7").details.get("index_tampering") is True
    assert any(e["event_type"] == "INDEX_TAMPERING" for e in cg.repo.list_events())


def test_rogue_key_inserted_into_index_is_not_trusted(cg, chain):
    """E5-C5: a key written straight into the signers table never entered the signed log."""
    from chainguard.crypto.canonical import canonical_json
    from chainguard.crypto.keys import compute_key_id, generate_private_key, public_key_b64
    from chainguard.crypto.signing import sign_bytes
    from chainguard.manifest.builder import load_envelope_raw, write_envelope

    rogue = generate_private_key()
    kid = compute_key_id(rogue.public_key())
    sql(cg, "INSERT INTO signers (key_id, identity, role, public_key_b64, created_at) VALUES (?,?,?,?,?)",
        (kid, f"training_pipeline@{cg.settings.identity_domain}", "training_pipeline",
         public_key_b64(rogue.public_key()), "2026-01-01T00:00:00Z"))
    path = cg.settings.envelope_path(chain["final"])
    raw = load_envelope_raw(path)
    raw["payload"]["signer"]["key_id"] = kid
    raw["signatures"] = [{"key_id": kid, "algorithm": "Ed25519", "sig": sign_bytes(rogue, canonical_json(raw["payload"]))}]
    write_envelope(raw, path)
    r = cg.verifier.verify(chain["final"])
    assert r.status == Status.FAILED and {"V3", "V4"} <= failed(r)
    assert "never trusted in the signed trust log" in r.check("V4").message


def test_truncating_the_trust_log_fails_closed(cg, chain):
    """E5-C6: dropping the last record rolls the log back; the pin notices."""
    cg.registry.revoke(chain["base"], "withdrawn")
    sql(cg, "UPDATE artifacts SET revoked = 0 WHERE artifact_id = ?", (chain["base"],))
    lines = [ln for ln in cg.settings.trust_log_path.read_bytes().split(b"\n") if ln.strip()]
    cg.settings.trust_log_path.write_bytes(b"\n".join(lines[:-1]) + b"\n")
    r = cg.verifier.verify(chain["final"])
    assert r.status == Status.FAILED and {"V3", "V4", "V7"} <= failed(r) and not r.trust_log_ok
    assert "rollback" in r.check("V7").message
    assert any(e["event_type"] == "TRUST_LOG_INVALID" for e in cg.repo.list_events())


def test_editing_a_trust_log_record_fails_closed(cg, chain):
    """E5-C7: the root signature no longer matches the edited entry."""
    import json

    from chainguard.crypto.canonical import canonical_json

    cg.registry.revoke(chain["base"], "withdrawn")
    lines = [ln for ln in cg.settings.trust_log_path.read_bytes().split(b"\n") if ln.strip()]
    rec = json.loads(lines[-1])
    rec["entry"]["reason"] = "never mind"
    lines[-1] = canonical_json(rec)
    cg.settings.trust_log_path.write_bytes(b"\n".join(lines) + b"\n")
    r = cg.verifier.verify(chain["final"])
    assert r.status == Status.FAILED and not r.trust_log_ok
    assert "signature by root key invalid" in r.check("V4").message


def test_deleting_the_trust_log_fails_closed(cg, chain):
    """E5-C8: no log, no trust."""
    assert cg.verifier.verify(chain["final"]).status == Status.VERIFIED
    cg.settings.trust_log_path.unlink()
    r = cg.verifier.verify(chain["final"])
    assert r.status == Status.FAILED and not r.trust_log_ok and {"V3", "V4", "V7"} <= failed(r)


def test_report_carries_the_pinned_trust_log_head(cg, chain):
    """Every report says which trust-log head it was verified against, and that head is the pin."""
    import json as _json

    r = cg.verifier.verify(chain["final"])
    assert r.trust_log_ok and r.trust_log_seq >= 4 and r.trust_log_head.startswith("sha256:")
    pin = _json.loads(cg.settings.trust_root_path.read_text())
    assert pin["head_seq"] == r.trust_log_seq and pin["head_hash"] == r.trust_log_head
    assert r.check("V7").message.endswith(f"(signed trust log #{r.trust_log_seq})")

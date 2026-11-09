"""Unit tests for the signed, append-only trust log (v0.4)."""

from __future__ import annotations

import json

import pytest

from chainguard.config import Settings
from chainguard.crypto.canonical import canonical_json
from chainguard.crypto.keys import compute_key_id, generate_private_key, public_key_b64
from chainguard.exceptions import KeyMismatchError, TrustLogError
from chainguard.trustlog import GENESIS_PREV, ROOT_ROLE, TrustLog, record_hash


@pytest.fixture
def log(tmp_path):
    settings = Settings(root=tmp_path / "ws")
    settings.ensure_dirs()
    return TrustLog(settings)


@pytest.fixture
def root():
    return generate_private_key()


def _subject(key, role="data_steward", identity=None):
    return {"key_id": compute_key_id(key.public_key()), "identity": identity or f"{role}@test",
            "role": role, "public_key_b64": public_key_b64(key.public_key())}


def test_uninitialised_log_is_not_ok(log):
    state = log.load()
    assert not state.ok and "no trust root pinned" in state.error
    with pytest.raises(TrustLogError):
        log.append("revoke_artifact", {"artifact_id": "x"}, "y", signer_key=generate_private_key())


def test_genesis_pin_and_replay(log, root):
    rec = log.initialise(root, "release_manager@test")
    assert rec["entry"]["seq"] == 1 and rec["entry"]["prev"] == GENESIS_PREV
    pin = log.pin()
    assert pin["root_key_id"] == compute_key_id(root.public_key()) and pin["head_seq"] == 1
    assert pin["head_hash"] == record_hash(rec)
    state = log.load()
    assert state.ok and state.head_seq == 1 and state.root_key_id == pin["root_key_id"]
    assert state.signer(pin["root_key_id"])["role"] == ROOT_ROLE
    with pytest.raises(TrustLogError):
        log.initialise(root, "again")


def test_records_chain_and_state_accumulates(log, root):
    log.initialise(root, "rm@test")
    k = generate_private_key()
    log.append("trust_key", _subject(k), signer_key=root)
    log.append("revoke_artifact", {"artifact_id": "a1"}, "withdrawn", signer_key=root)
    log.append("revoke_key", {"key_id": compute_key_id(k.public_key())}, "lost", signer_key=root)
    state = log.load()
    assert state.ok and state.head_seq == 4
    records = [json.loads(ln) for ln in log.log_path.read_text().splitlines()]
    for previous, current in zip(records, records[1:], strict=False):
        assert current["entry"]["prev"] == record_hash(previous)
    assert state.artifact_revocation("a1")["reason"] == "withdrawn"
    assert state.signer(compute_key_id(k.public_key()))["revoked_reason"] == "lost"
    assert state.active_signers_for_role("data_steward") == []


def test_only_the_root_key_may_append(log, root):
    log.initialise(root, "rm@test")
    with pytest.raises(KeyMismatchError):
        log.append("revoke_artifact", {"artifact_id": "a"}, "x", signer_key=generate_private_key())
    with pytest.raises(TrustLogError):
        log.append("bless", {"artifact_id": "a"}, signer_key=root)


def test_truncation_is_detected(log, root):
    log.initialise(root, "rm@test")
    log.append("revoke_artifact", {"artifact_id": "a1"}, "withdrawn", signer_key=root)
    lines = log.log_path.read_text().splitlines()
    log.log_path.write_text(lines[0] + "\n")
    state = log.load()
    assert not state.ok and "rollback" in state.error


def test_appended_forgery_is_detected(log, root):
    log.initialise(root, "rm@test")
    state = log.load()
    forged_entry = {"seq": 2, "prev": state.head_hash, "ts": "t", "action": "revoke_artifact",
                    "subject": {"artifact_id": "a"}}
    rec = {"entry": forged_entry, "key_id": state.root_key_id, "sig": "AAAA"}
    with log.log_path.open("ab") as fh:
        fh.write(canonical_json(rec) + b"\n")
    state = log.load()
    assert not state.ok and "signature" in state.error


def test_edited_record_is_detected(log, root):
    log.initialise(root, "rm@test")
    log.append("revoke_artifact", {"artifact_id": "a1"}, "withdrawn", signer_key=root)
    lines = log.log_path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["entry"]["subject"]["artifact_id"] = "someone-else"
    lines[1] = canonical_json(rec).decode()
    log.log_path.write_text("\n".join(lines) + "\n")
    assert not log.load().ok


def test_substituted_log_with_other_root_is_detected(log, root, tmp_path):
    log.initialise(root, "rm@test")
    other = TrustLog(Settings(root=tmp_path / "other"))
    other.settings.ensure_dirs()
    other.initialise(generate_private_key(), "rm@evil")
    log.log_path.write_bytes(other.log_path.read_bytes())
    state = log.load()
    assert not state.ok


def test_root_rotation(log, root):
    log.initialise(root, "rm@test")
    new = generate_private_key()
    subj = dict(_subject(new, ROOT_ROLE, "rm@test"), replaces=compute_key_id(root.public_key()))
    log.append("rotate_root", subj, "rotated", signer_key=root)
    assert log.pin()["root_key_id"] == compute_key_id(new.public_key())
    log.append("revoke_artifact", {"artifact_id": "a1"}, "x", signer_key=new)   # new root signs
    with pytest.raises(KeyMismatchError):
        log.append("revoke_artifact", {"artifact_id": "a2"}, "x", signer_key=root)   # old root cannot
    state = log.load()
    assert state.ok and state.head_seq == 3
    assert state.signer(compute_key_id(root.public_key()))["revoked_reason"] == "rotated"


def test_missing_log_file_is_not_ok(log, root):
    log.initialise(root, "rm@test")
    log.log_path.unlink()
    state = log.load()
    assert not state.ok and "missing" in state.error


def test_repair_moves_a_stale_pin_forward_but_never_backward(log, root):
    log.initialise(root, "rm@test")
    log.append("revoke_artifact", {"artifact_id": "a1"}, "withdrawn", signer_key=root)
    good_pin = log.pin()
    # simulate a crash between writing record 2 and the pin: pin still names record 1
    state = log._load(check_pin=False)
    stale = dict(good_pin, head_seq=1, head_hash=state.entries[0]["hash"])
    log._write_pin(stale)
    assert not log.load().ok and "does not match the pinned head" in log.load().error
    with pytest.raises(TrustLogError):
        log.repair_pin(generate_private_key())          # not the root key
    repaired = log.repair_pin(root)
    assert repaired["head_seq"] == 2 and repaired["head_hash"] == good_pin["head_hash"] and log.load().ok
    # a truncated log is never "repaired" into legitimacy
    lines = log.log_path.read_text().splitlines()
    log.log_path.write_text(lines[0] + "\n")
    with pytest.raises(TrustLogError, match="truncation"):
        log.repair_pin(root)


def test_concurrent_appends_keep_the_chain_intact(log, root):
    import threading

    log.initialise(root, "rm@test")
    errors: list[Exception] = []

    def worker(i: int) -> None:
        try:
            log.append("revoke_artifact", {"artifact_id": f"a{i}"}, "x", signer_key=root)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    state = log.load()
    assert state.ok and state.head_seq == 13 and len(state.revoked_artifacts) == 12

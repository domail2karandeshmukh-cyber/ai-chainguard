import base64
import os
import stat

import pytest

from chainguard.crypto.keys import (
    compute_key_id,
    generate_private_key,
    load_private_key_for_role,
    private_key_to_pem,
    public_key_b64,
    save_private_key,
)
from chainguard.crypto.signing import sign_bytes, verify_bytes
from chainguard.exceptions import KeyNotFoundError


def test_sign_verify_roundtrip():
    k = generate_private_key()
    sig = sign_bytes(k, b"payload")
    assert verify_bytes(public_key_b64(k.public_key()), b"payload", sig)


def test_modified_data_fails():
    k = generate_private_key()
    sig = sign_bytes(k, b"payload")
    assert not verify_bytes(public_key_b64(k.public_key()), b"payloaD", sig)


def test_wrong_key_fails():
    k1, k2 = generate_private_key(), generate_private_key()
    sig = sign_bytes(k1, b"payload")
    assert not verify_bytes(public_key_b64(k2.public_key()), b"payload", sig)


def test_ed25519_is_deterministic():
    k = generate_private_key()
    assert sign_bytes(k, b"m") == sign_bytes(k, b"m")


@pytest.mark.parametrize("bad_sig", ["", "not-base64!!", base64.b64encode(b"short").decode(),
                                     base64.b64encode(b"\x00" * 64).decode()])
def test_malformed_signatures_return_false(bad_sig):
    k = generate_private_key()
    assert verify_bytes(public_key_b64(k.public_key()), b"payload", bad_sig) is False


def test_malformed_public_key_returns_false():
    k = generate_private_key()
    assert verify_bytes("AAAA", b"x", sign_bytes(k, b"x")) is False


def test_key_id_format():
    kid = compute_key_id(generate_private_key().public_key())
    assert kid.startswith("ed25519:") and len(kid) == len("ed25519:") + 16


def test_private_key_file_permissions_and_no_overwrite(tmp_path):
    k = generate_private_key()
    p = save_private_key(k, tmp_path / "role.pem")
    if os.name == "posix":
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        save_private_key(k, p)


def test_load_from_file_and_env(tmp_path, monkeypatch):
    k = generate_private_key()
    save_private_key(k, tmp_path / "data_steward.pem")
    loaded = load_private_key_for_role("data_steward", tmp_path)
    assert compute_key_id(loaded.public_key()) == compute_key_id(k.public_key())

    k2 = generate_private_key()
    monkeypatch.setenv("CHAINGUARD_KEY_DATA_STEWARD", private_key_to_pem(k2).decode())
    from_env = load_private_key_for_role("data_steward", tmp_path)
    assert compute_key_id(from_env.public_key()) == compute_key_id(k2.public_key())


def test_missing_key_raises(tmp_path):
    with pytest.raises(KeyNotFoundError):
        load_private_key_for_role("nobody", tmp_path)


def test_passphrase_encrypted_key(tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINGUARD_KEY_PASSPHRASE", "s3cret")
    k = generate_private_key()
    p = save_private_key(k, tmp_path / "r.pem")
    assert b"ENCRYPTED" in p.read_bytes()
    assert compute_key_id(load_private_key_for_role("r", tmp_path).public_key()) == compute_key_id(k.public_key())

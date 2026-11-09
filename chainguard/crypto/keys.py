"""Ed25519 key generation, storage and loading.

Why Ed25519 (see docs/07_technical_description.md for the full comparison):
* deterministic signatures: no per-signature random nonce, so no nonce-reuse key
  leaks (the classic ECDSA failure);
* 32-byte public keys, 64-byte signatures, fast verification;
* misuse-resistant API in ``cryptography`` and supported by Sigstore, SSH, age.

Key handling rules enforced here:
* private keys are NEVER in source code; they are generated at runtime into
  ``keys/<role>.pem`` (git-ignored, mode 0600) or injected via an environment
  variable ``CHAINGUARD_KEY_<ROLE>`` (CI secret);
* an optional passphrase (``CHAINGUARD_KEY_PASSPHRASE``) encrypts key files at rest.

PROTOTYPE NOTE: production keys belong in an HSM / cloud KMS, or should be replaced
by short-lived keyless certificates (Sigstore Fulcio) so no long-lived key exists.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from chainguard.crypto.hashing import sha256_bytes
from chainguard.exceptions import KeyNotFoundError

KEY_ID_PREFIX = "ed25519:"


def generate_private_key() -> Ed25519PrivateKey:
    """Generate a new Ed25519 private key from the OS CSPRNG."""
    return Ed25519PrivateKey.generate()


def public_key_raw(public_key: Ed25519PublicKey) -> bytes:
    """The 32 raw bytes of an Ed25519 public key."""
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_key_b64(public_key: Ed25519PublicKey) -> str:
    return base64.b64encode(public_key_raw(public_key)).decode("ascii")


def public_key_from_b64(b64: str) -> Ed25519PublicKey:
    raw = base64.b64decode(b64, validate=True)
    return Ed25519PublicKey.from_public_bytes(raw)


def compute_key_id(public_key: Ed25519PublicKey) -> str:
    """Stable key reference: 'ed25519:' + first 16 hex chars of SHA-256(raw public key).

    16 hex chars = 64 bits, enough to avoid accidental collisions among a handful of
    keys. The key id is only a *lookup hint*: verification always uses the full
    public key from the trust store, never the id itself.
    """
    return KEY_ID_PREFIX + sha256_bytes(public_key_raw(public_key))[:16]


def _passphrase() -> bytes | None:
    value = os.environ.get("CHAINGUARD_KEY_PASSPHRASE")
    return value.encode("utf-8") if value else None


def private_key_to_pem(private_key: Ed25519PrivateKey, passphrase: bytes | None = None) -> bytes:
    encryption: serialization.KeySerializationEncryption
    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase)
    else:
        encryption = serialization.NoEncryption()
    return private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )


def save_private_key(private_key: Ed25519PrivateKey, path: str | Path, overwrite: bool = False) -> Path:
    """Write a private key as PKCS#8 PEM with owner-only permissions (0600)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing key {path}")
    pem = private_key_to_pem(private_key, _passphrase())
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)  # permissions set atomically at creation
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return path


def load_private_key_pem(pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=_passphrase())
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyNotFoundError("Key is not an Ed25519 private key")
    return key


def env_var_for_role(role: str) -> str:
    return f"CHAINGUARD_KEY_{role.upper()}"


def load_private_key_for_role(role: str, keys_dir: str | Path) -> Ed25519PrivateKey:
    """Load a role's private key: environment variable first (CI), then key file."""
    env_pem = os.environ.get(env_var_for_role(role))
    if env_pem:
        return load_private_key_pem(env_pem.encode("utf-8"))
    path = Path(keys_dir) / f"{role}.pem"
    if not path.exists():
        raise KeyNotFoundError(
            f"No private key for role '{role}' (looked for ${env_var_for_role(role)} and {path}). "
            "Run: python -m cli.main keys init"
        )
    return load_private_key_pem(path.read_bytes())

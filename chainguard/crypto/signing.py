"""Ed25519 signing and verification over raw bytes.

These functions are deliberately tiny: the security comes from *what* is signed
(canonical manifest bytes, see manifest/builder.py) and *which key is trusted for
which role* (see trust.py and provenance/policy.py), not from wrapping the library.
"""

from __future__ import annotations

import base64
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainguard.crypto.keys import public_key_from_b64

ALGORITHM = "Ed25519"


def sign_bytes(private_key: Ed25519PrivateKey, data: bytes) -> str:
    """Sign ``data``; return the 64-byte signature as base64."""
    return base64.b64encode(private_key.sign(data)).decode("ascii")


def verify_bytes(public_key_b64: str, data: bytes, signature_b64: str) -> bool:
    """Return True only if ``signature_b64`` is a valid Ed25519 signature of ``data``.

    Any malformed input (bad base64, wrong length, invalid point) returns False
    rather than raising, so callers cannot accidentally treat an exception path as
    success.
    """
    try:
        public_key = public_key_from_b64(public_key_b64)
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(signature, data)
        return True
    except (InvalidSignature, ValueError, binascii.Error, TypeError):
        return False

"""Canonical JSON serialisation.

A signature is computed over *bytes*, but a manifest is a JSON *object*. The same
object can be written in many byte forms (key order, spaces, unicode escapes), and a
verifier that re-serialises differently from the signer would reject a valid
signature, or worse, two parties could disagree about what was signed.

We therefore define one canonical form:

* keys sorted lexicographically at every level,
* no insignificant whitespace (``","`` and ``":"`` separators),
* UTF-8 output, non-ASCII characters kept as-is,
* NaN and Infinity forbidden (not valid JSON).

LIMIT OF THIS VERSION: this is close to, but not identical to, RFC 8785 (JSON
Canonicalization Scheme). JCS additionally fixes the textual form of floating-point
numbers across languages. Python's float ``repr`` is deterministic, so a
Python-only system is safe; a multi-language production system should use JCS.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Serialise ``obj`` to canonical UTF-8 JSON bytes."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

"""Merkle trees (RFC 6962 / RFC 9162 construction).

Used for two purposes:

1. **Dataset row tree.** Each line of a CSV is a leaf. The signed manifest stores the
   root. If the file hash no longer matches, comparing current leaves against the
   stored leaf list tells *which rows* changed (evidence for Scenario A). Inclusion
   proofs let a party prove one sample belongs to a signed dataset without sharing
   the whole dataset.
2. **Release root.** At deployment, the manifest digests of a model and all its
   ancestors are the leaves; one 32-byte root summarises the whole supply chain and
   is what you would publish to a transparency log.

Security details
----------------
* Domain separation: leaf = H(0x00 || data), node = H(0x01 || left || right). Without
  it, an internal node could be presented as a leaf (second-preimage attack).
* Unbalanced trees split at the largest power of two below n (RFC 6962) instead of
  duplicating the last node, avoiding the Bitcoin CVE-2012-2459 ambiguity where two
  different leaf lists produce the same root.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from chainguard.crypto.hashing import PREFIX

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _split_point(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root_from_leaf_hashes(leaves: Sequence[bytes]) -> bytes:
    """Root over already-hashed leaves. The empty tree's root is SHA-256('')."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    return _mth(leaves, 0, n)  # recursive RFC 6962 split; depth is only log2(n)


def _mth(leaves: Sequence[bytes], lo: int, hi: int) -> bytes:
    n = hi - lo
    if n == 1:
        return leaves[lo]
    k = _split_point(n)
    return node_hash(_mth(leaves, lo, lo + k), _mth(leaves, lo + k, hi))


def inclusion_proof(leaves: Sequence[bytes], index: int) -> list[bytes]:
    """Audit path for leaf ``index`` (RFC 6962 section 2.1.1)."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    return _path(leaves, index, 0, len(leaves))


def _path(leaves: Sequence[bytes], m: int, lo: int, hi: int) -> list[bytes]:
    n = hi - lo
    if n == 1:
        return []
    k = _split_point(n)
    if m < k:
        return _path(leaves, m, lo, lo + k) + [_mth(leaves, lo + k, hi)]
    return _path(leaves, m - k, lo + k, hi) + [_mth(leaves, lo, lo + k)]


def verify_inclusion(leaf: bytes, index: int, tree_size: int, proof: Sequence[bytes], root: bytes) -> bool:
    """Verify an inclusion proof (RFC 9162 section 2.1.3.2)."""
    if index >= tree_size:
        return False
    fn, sn, r = index, tree_size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# ---- dataset helpers ---------------------------------------------------------

def line_leaf_hashes(data: bytes) -> list[bytes]:
    """One leaf per line (header included). Line endings are not part of the leaf;
    the whole-file SHA-256 still covers them."""
    return [leaf_hash(line) for line in data.splitlines()]


def file_line_leaf_hashes(path: str | Path) -> list[bytes]:
    return line_leaf_hashes(Path(path).read_bytes())


def root_hex(root: bytes) -> str:
    return PREFIX + root.hex()


def diff_leaves(signed: Sequence[bytes], current: Sequence[bytes], limit: int = 50) -> dict[str, Any]:
    """Compare the signed leaf list with the current one.

    Returns changed line indices (same position, different content) and counts of
    added/removed lines. Line 0 is the CSV header, so data row i is line i.
    """
    common = min(len(signed), len(current))
    changed = [i for i in range(common) if signed[i] != current[i]]
    return {
        "changed_lines": changed[:limit],
        "changed_count": len(changed),
        "added_lines": max(0, len(current) - len(signed)),
        "removed_lines": max(0, len(signed) - len(current)),
        "signed_leaf_count": len(signed),
        "current_leaf_count": len(current),
    }


def release_root(manifest_digests: Sequence[str]) -> str:
    """Merkle root over a set of manifest digests (order-independent: sorted first)."""
    leaves = [leaf_hash(d.encode("ascii")) for d in sorted(set(manifest_digests))]
    return root_hex(merkle_root_from_leaf_hashes(leaves))

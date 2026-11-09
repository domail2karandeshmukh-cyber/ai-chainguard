import hashlib

import pytest

from chainguard.provenance.merkle import (
    diff_leaves,
    inclusion_proof,
    leaf_hash,
    line_leaf_hashes,
    merkle_root_from_leaf_hashes,
    node_hash,
    release_root,
    verify_inclusion,
)


def leaves(n):
    return [leaf_hash(f"row-{i}".encode()) for i in range(n)]


def test_empty_and_single_leaf_roots():
    assert merkle_root_from_leaf_hashes([]) == hashlib.sha256(b"").digest()
    one = leaves(1)
    assert merkle_root_from_leaf_hashes(one) == one[0]


def test_domain_separation():
    a, b = leaf_hash(b"a"), leaf_hash(b"b")
    # An internal node is never equal to a leaf over the same bytes.
    assert node_hash(a, b) != leaf_hash(a + b)
    assert leaf_hash(b"x") != hashlib.sha256(b"x").digest()


def test_rfc6962_shape_for_three_leaves():
    lf = leaves(3)
    assert merkle_root_from_leaf_hashes(lf) == node_hash(node_hash(lf[0], lf[1]), lf[2])


def test_no_duplicate_last_leaf_ambiguity():
    # Bitcoin-style duplication would make [a, b, c] and [a, b, c, c] share a root.
    lf = leaves(3)
    assert merkle_root_from_leaf_hashes(lf) != merkle_root_from_leaf_hashes(lf + [lf[2]])


@pytest.mark.parametrize("n", list(range(1, 18)) + [100, 1437])
def test_every_inclusion_proof_verifies(n):
    lf = leaves(n)
    root = merkle_root_from_leaf_hashes(lf)
    for i in range(0, n, max(1, n // 25)):
        assert verify_inclusion(lf[i], i, n, inclusion_proof(lf, i), root)


def test_wrong_proofs_fail():
    lf = leaves(10)
    root = merkle_root_from_leaf_hashes(lf)
    proof = inclusion_proof(lf, 3)
    assert not verify_inclusion(lf[4], 3, 10, proof, root)          # wrong leaf
    assert not verify_inclusion(lf[3], 4, 10, proof, root)          # wrong index
    assert not verify_inclusion(lf[3], 3, 100, proof, root)         # wrong tree size (path shape differs)
    assert not verify_inclusion(lf[3], 3, 10, proof[:-1], root)     # truncated proof


def test_diff_leaves_localises_changes():
    old = line_leaf_hashes(b"h\n1\n2\n3\n")
    new = line_leaf_hashes(b"h\n1\nX\n3\n4\n")
    d = diff_leaves(old, new)
    assert d["changed_lines"] == [2] and d["added_lines"] == 1 and d["removed_lines"] == 0


def test_release_root_is_order_independent():
    ds = ["sha256:aa", "sha256:bb", "sha256:cc"]
    assert release_root(ds) == release_root(list(reversed(ds)))
    assert release_root(ds) != release_root(ds[:2])

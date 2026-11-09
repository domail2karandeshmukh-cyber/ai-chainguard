"""SHA-256 hashing of artifacts.

Design notes
------------
* Files are hashed in fixed-size chunks (1 MiB) so a multi-GB model never has to fit
  in memory. Memory use is constant, time is linear in file size (see benchmark).
* Hex digests are lower-case. Values stored in manifests that identify *manifests*
  or *Merkle roots* carry an explicit ``sha256:`` prefix (algorithm agility, as in
  OCI/in-toto); the raw file hash in ``subject.sha256`` is plain hex because the
  field name already states the algorithm.
* SHA-256 gives 128-bit collision resistance, which is ample here. SHA-3/BLAKE3
  would be drop-in alternatives; SHA-256 is chosen for ecosystem compatibility
  (OCI, Sigstore, SLSA, Git's SHA-256 mode).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK_SIZE = 1024 * 1024  # 1 MiB
PREFIX = "sha256:"


def sha256_bytes(data: bytes) -> str:
    """Hex SHA-256 of an in-memory byte string."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, chunk_size: int = CHUNK_SIZE) -> str:
    """Hex SHA-256 of a file, streamed in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def sha256_directory(path: str | Path) -> str:
    """Deterministic hash of a directory tree (e.g. a sharded model or HF repo).

    The digest covers every file's relative path and content hash, sorted by path,
    so renaming, adding, removing or modifying any file changes the result. Empty
    directories and file permissions are deliberately ignored.
    """
    root = Path(path)
    h = hashlib.sha256()
    for file in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = file.relative_to(root).as_posix()
        h.update(rel.encode("utf-8") + b"\0" + sha256_file(file).encode("ascii") + b"\n")
    return h.hexdigest()


def prefixed(hex_digest: str) -> str:
    """'abc...' -> 'sha256:abc...'."""
    return hex_digest if hex_digest.startswith(PREFIX) else PREFIX + hex_digest


def strip_prefix(digest: str) -> str:
    """'sha256:abc...' -> 'abc...'."""
    return digest[len(PREFIX):] if digest.startswith(PREFIX) else digest

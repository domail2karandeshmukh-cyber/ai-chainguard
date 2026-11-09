import hashlib

from chainguard.crypto.hashing import prefixed, sha256_bytes, sha256_directory, sha256_file, strip_prefix


def test_known_vector():
    # FIPS 180-2 test vector for "abc"
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_streamed_file_hash_equals_in_memory_hash(tmp_path):
    data = bytes(range(256)) * 5000  # 1.28 MB, spans several chunks
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    assert sha256_file(p) == hashlib.sha256(data).hexdigest()
    assert sha256_file(p, chunk_size=7) == hashlib.sha256(data).hexdigest()


def test_single_byte_change_changes_hash(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"a" * 1000)
    h1 = sha256_file(p)
    p.write_bytes(b"a" * 999 + b"b")
    assert sha256_file(p) != h1


def test_directory_hash_covers_names_and_content(tmp_path):
    d = tmp_path / "model"
    d.mkdir()
    (d / "a.bin").write_bytes(b"1")
    (d / "b.bin").write_bytes(b"2")
    h = sha256_directory(d)
    (d / "b.bin").rename(d / "c.bin")
    assert sha256_directory(d) != h
    (d / "c.bin").rename(d / "b.bin")
    assert sha256_directory(d) == h
    (d / "a.bin").write_bytes(b"x")
    assert sha256_directory(d) != h


def test_prefix_helpers():
    assert prefixed("ab") == "sha256:ab"
    assert prefixed("sha256:ab") == "sha256:ab"
    assert strip_prefix("sha256:ab") == "ab"

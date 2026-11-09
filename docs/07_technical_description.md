# Technical description

## 1. Cryptographic choices

### Hashing: SHA-256

128-bit collision resistance, hardware-accelerated on modern CPUs, and the common digest of OCI, Sigstore, SLSA and in-toto. Files are streamed in 1 MiB chunks (constant memory). Measured throughput: ~1.05 GB/s (256 MiB in 244 ms). Alternatives: SHA-3 (different construction, slower in software), BLAKE3 (faster, parallel, less ecosystem support).

### Signatures: Ed25519 (RFC 8032)

| Property | Ed25519 | ECDSA P-256 | RSA-PSS 3072 |
| --- | --- | --- | --- |
| Signature size | 64 B | ~64–72 B | 384 B |
| Public key | 32 B | 33/65 B | 384 B |
| Per-signature randomness | None (deterministic) | Required; reuse leaks the key | Required (salt) |
| Measured sign / verify here | 0.05 / 0.2 ms | — | — |
| FIPS 186-5 | Yes (since 2023) | Yes | Yes |

Deterministic signing removes the nonce-reuse failure that has leaked ECDSA keys in practice. None of the three is post-quantum; ML-DSA (FIPS 204) is the migration path, and the `algorithm` field in each signature entry allows it.

### Canonical serialisation

Signatures are over `canonical_json(payload)`: sorted keys, compact separators, UTF-8, no NaN. The verifier digests the payload **as read from disk** (not re-serialised through Pydantic), so even an extra field breaks verification. Production across languages: RFC 8785 (JCS).

### Merkle trees

RFC 6962 construction with leaf/node domain separation (0x00 / 0x01) and power-of-two splitting (no duplicate-last-leaf ambiguity). One leaf per CSV line. The leaf list is stored as a sidecar; it is only trusted if it reproduces the signed root, which lets V2 report exactly which lines changed. Cost: 2 ms per 1,000 rows, ~2 s per 1,000,000 rows.

### Release root

At deployment, the Merkle root over the sorted manifest digests of the model and all its ancestors. One 32-byte value identifies the whole supply chain of a release; it is the value to publish in a transparency log.

## 2. Manifest and envelope

```json
{
  "payload_type": "application/vnd.chainguard.manifest+json; version=1",
  "payload": {
    "schema_version": "1.0", "artifact_id": "uuid4", "artifact_name": "...",
    "artifact_type": "dataset|base_model|finetuned_model|deployment_record",
    "version": "1.0.0", "pipeline_stage": "stage1_dataset|...|stage4_deployment",
    "subject": {"uri": "workspace-relative path", "sha256": "hex", "size_bytes": 0,
                "media_type": "...", "merkle": {"root": "sha256:...", "leaf_count": 0, "leaf_unit": "csv_line", "hash": "sha256"}},
    "parents": [{"artifact_id": "...", "manifest_digest": "sha256:...", "relation": "trained_on"}],
    "provenance": {"source": "...", "builder": "...", "environment": {...}, "parameters": {...}, "metrics": {...}},
    "semantic_checks": [{"name": "...", "status": "pass|flag|skip", "summary": "...", "details": {}}],
    "created_at": "ISO-8601 UTC",
    "signer": {"identity": "role@domain", "role": "...", "key_id": "ed25519:<16 hex>"}
  },
  "signatures": [{"key_id": "...", "algorithm": "Ed25519", "sig": "base64"}],
  "manifest_digest": "sha256:... (convenience copy, never trusted)"
}
```

Verification status is **not** signed; it changes after signing and lives in SQLite as a cache. Revocation status **is** signed since v0.4: each revocation (and each key-trust decision) is a record of the hash-chained trust log signed by the `release_manager` root key (`chainguard/trustlog.py`), pinned in `keys/trust_root.json`.

## 3. Verifier

Checks V0–V9 always all run (complete report). Recursion is memoised per call; depth is bounded (32) and cycles are reported. Metrics recorded per call: `hash`, `verify_signature`, `verify_full`.

## 4. TOCTOU-safe consumption

`chainguard.verification.verified_io.open_verified()` verifies the chain, re-reads the envelope and checks its digest equals the verified one, reads the file **once**, hashes those bytes, and returns them. Training and the gateway load data/models from those bytes only.

## 5. ML pipeline

sklearn `digits` (1,797 8×8 images). CNN: conv16–conv32–maxpool–fc64–fc10 (~38 k parameters). Base training 15 epochs Adam lr 1e-3; fine-tuning 8 epochs lr 5e-4. Weights stored as **safetensors**. Clean test accuracy 95.0 %. Training ~1.4 s on CPU.

## 6. Semantic checks (pre-attestation)

| Check | Detects | Known blind spot |
| --- | --- | --- |
| label_distribution (chi-square vs reference, α = 0.001) | Heavy label flipping, class-targeted poisoning | Low poisoning rates |
| duplicate_rows (> 2 %) | Amplification by duplication | Near-duplicates |
| corner_trigger (all four pixels of a 2×2 corner ≥ 12) | BadNets corner-patch triggers | Any other trigger shape (E4) |

False-positive rate on the clean splits: 0 flags (the first version used the patch *mean* and produced 11 false positives on clean digits, mostly 1s and 7s; switching to the patch *minimum* fixed it — record this in the journal).

## 7. Storage

SQLite with WAL and `synchronous=NORMAL`; one short-lived connection per operation (thread-safe for FastAPI). Tables: `signers`, `artifacts`, `artifact_parents`, `verification_runs`, `security_events`, `metrics`. Registration cost is dominated by index writes (~11 ms per artifact); cryptographic work is < 1 ms for small artifacts.

## 8. Prototype-only choices

See the table in the README: file-based keys, DB trust store, no API authentication, demo endpoints, signed environment claims instead of hardware attestation, heuristic content checks.

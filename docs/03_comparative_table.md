# Comparative table of approaches

*Draft for the state-of-the-art section. "Partial" means the approach helps only under conditions given in the notes. Check every row against the references before submission.*

| Approach | Detects post-hoc tampering | Proves origin (who) | Links artifacts across stages | Detects poisoned / backdoored content | Key management burden | External infrastructure | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Plain hashes (checksums) | Yes, if the hash is obtained from a trusted channel | No | No | No | None | None | Hash and file stored together can both be replaced |
| Digital signatures (Ed25519/ECDSA) | Yes | Yes (key holder) | No, unless parents are signed into the payload | No | High (long-lived keys, revocation) | None | Basis of AI-ChainGuard |
| Sigstore / cosign (keyless) | Yes | Yes (OIDC identity) | No (per artifact) | No | Low (short-lived certs) | Fulcio, Rekor, OIDC provider | Public transparency log gives tamper-evident history |
| OpenSSF Model Signing | Yes (whole model directory) | Yes | No | No | Low–medium | Sigstore or PKI | Model-specific packaging of signing |
| in-toto attestations | Yes | Yes | Yes (layout of steps) | No | Medium | None required | Closest to AI-ChainGuard's stage/role policy |
| SLSA provenance (applied to ML) | Yes | Yes (builder identity) | Partial (build inputs recorded) | No | Medium | Hardened builder | Strength depends on non-forgeable builder |
| Model cards / datasheets | No | No | No (descriptive) | No | None | None | Transparency only; unsigned by default |
| AI/ML-BOM (CycloneDX, SPDX 3.0) | Only if signed | Only if signed | Yes (inventory) | No | Depends | None | Inventory, not verification |
| Blockchain anchoring | Yes (history) | Partial | Yes | No | Medium | Ledger network | Adds cost; transparency logs give similar evidence |
| Semantic checks (validation, backdoor scans) | No | No | No | **Partial** | None | None | Heuristic, evadable, false positives |
| **AI-ChainGuard (this project)** | Yes (V1, V2 row-level) | Yes (role-bound keys, V3, V4) | **Yes** (hash-linked parents, V5, V6) | Partial (V9 heuristics, WARNING only) | Medium (file keys, prototype) | None | Policy (V8) + revocation propagation (V7) |

**Reading the table:** no row has "Yes" in the *content* column. Integrity mechanisms and semantic defences answer different questions; a credible AI supply-chain control combines both and states which one produced each conclusion.

# State of the art — AI supply-chain integrity

*Template with section plan and reading list. Target: 3–5 pages. Each member owns one approach (see roadmap). Before submission, open every reference and check titles, years and claims; entries marked [verify] were listed from memory.*

## 1. Why AI supply chains are a distinct problem (≈ ½ page)

- Software: readable source → deterministic build → binary; reproducible builds let anyone re-derive and diff.
- AI: data + code + hyper-parameters + randomness → weights. Not readable, rarely reproducible, behaviour only testable.
- Threat classes: data poisoning and backdoors (BadNets, Gu et al., 2017); malicious serialisation (pickle code execution in model files); model substitution; compromised training/fine-tuning infrastructure; untrusted pretrained models.
- Frameworks naming the risk: OWASP Machine Learning Security Top 10 (ML06 "AI supply chain attacks") [verify numbering]; MITRE ATLAS (adversary tactics for ML systems); NIST AI RMF 1.0 (2023).

## 2. Cryptographic signing and attestation (≈ 1 page) — owner: MEKALA Rambabu

- Digital signatures over artifact digests; detached signatures; envelopes (DSSE) and statements (in-toto attestation framework).
- Key management problem → **Sigstore**: Fulcio (short-lived certificates bound to OIDC identities), Rekor (transparency log), cosign. Keyless signing removes long-lived keys but adds dependency on public infrastructure.
- **OpenSSF Model Signing (OMS)** / `model_signing` library: signing ML model directories with Sigstore or PKI; v1.0 released in 2025 [verify].
- What signatures prove: integrity and origin of bytes. What they do not: benign content.

## 3. Provenance frameworks (≈ 1 page) — owner: Karan DESHMUKH

- **SLSA** (Supply-chain Levels for Software Artifacts) v1.0 (2023): build provenance levels, non-forgeable provenance from hardened builders. Discussion: mapping to ML ("SLSA for ML") — training as the build step; the dataset as a build input.
- **in-toto**: layout of supply-chain steps, functionaries and keys; closest conceptual match to AI-ChainGuard's stage/role policy.
- **Hash-linked structures and Merkle trees**: Git, Certificate Transparency (RFC 6962/9162), dataset-level Merkle trees for sample inclusion proofs.
- Blockchain anchoring: tamper-evident history; costs and trust assumptions versus transparency logs.

## 4. Documentation and inventory approaches (≈ ½ page) — owner: DAMA Dola Krishna

- **Model cards** (Mitchell et al., 2019) and **datasheets for datasets** (Gebru et al., 2018/2021): transparency, not integrity; unsigned by default.
- **AI/ML bills of materials**: CycloneDX ML-BOM (from v1.5, 2023), SPDX 3.0 AI and Dataset profiles (2024) [verify]. Inventory of components; integrity depends on signing the BOM.

## 5. Content-level (semantic) defences (≈ 1 page) — owner: JOGI Sudheer reddy

- Data validation and outlier detection; label-distribution tests.
- Backdoor detection: activation clustering (Chen et al., 2018), spectral signatures (Tran et al., 2018), Neural Cleanse (Wang et al., 2019), STRIP (Gao et al., 2019).
- Limits: adaptive attackers, clean-label poisoning, cost, false positives. Evidence, not proof.
- Practical poisoning of web-scale datasets (Carlini et al., 2023/2024) — motivates attestation at data collection time.

## 6. Safe serialisation (≈ ¼ page)

- Pickle-based `torch.save` / `.pkl`: arbitrary code execution on load; reports of malicious models on public hubs.
- **safetensors**: header + raw tensors, no code execution; scanners (e.g. picklescan) as mitigation for legacy formats.

## 7. Gap and positioning (≈ ½ page)

Existing tools sign *individual* artifacts (cosign, OMS) or describe them (model cards, ML-BOMs). Fewer prototypes **link** datasets, base models, fine-tuned models and deployments into one verifiable chain with role-based policy and revocation, and fewer still **measure** the boundary between cryptographic integrity and semantic trust. AI-ChainGuard contributes: (1) an end-to-end hash-linked attestation chain with a policy-enforcing verifier; (2) row-level dataset Merkle localisation; (3) an explicit, measured demonstration that signed poison verifies (Scenario E).

See `03_comparative_table.md` for the side-by-side comparison.

## References (to complete in the chosen citation style)

1. Gu, Dolan-Gavitt, Garg. BadNets: Identifying vulnerabilities in the machine learning model supply chain. 2017.
2. Mitchell et al. Model Cards for Model Reporting. FAT* 2019.
3. Gebru et al. Datasheets for Datasets. CACM 2021.
4. Chen et al. Detecting Backdoor Attacks on Deep Neural Networks by Activation Clustering. 2018.
5. Tran, Li, Madry. Spectral Signatures in Backdoor Attacks. NeurIPS 2018.
6. Wang et al. Neural Cleanse. IEEE S&P 2019.
7. Torres-Arias et al. in-toto: Providing farm-to-table guarantees for bits and bytes. USENIX Security 2019.
8. Newman, Meyers, Torres-Arias. Sigstore: Software Signing for Everybody. ACM CCS 2022.
9. SLSA specification v1.0. slsa.dev, 2023.
10. Laurie, Langley, Kasper. RFC 6962 Certificate Transparency (2013); RFC 9162 (2021).
11. Bernstein et al. High-speed high-security signatures (Ed25519). 2012; RFC 8032 (2017).
12. Carlini et al. Poisoning Web-Scale Training Datasets is Practical. IEEE S&P 2024.
13. NIST AI Risk Management Framework 1.0, 2023.
14. OpenSSF Model Signing specification [verify version/date].

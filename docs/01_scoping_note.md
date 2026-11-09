# Scoping note — AI-ChainGuard

*Template with draft content. Target length: 2–3 pages. Owner: Karan DESHMUKH. Replace bracketed text; keep the section order.*

**Team:** Karan DESHMUKH, JOGI Sudheer reddy, DAMA Dola Krishna, MEKALA Rambabu · **Programme:** ESAIP M1 Cybersecurity & Data Science · **Duration:** 8 weeks · **Date:** [date]

## 1. Context (≈ ½ page)

Enterprises increasingly assemble AI systems from parts they did not create: public datasets, pretrained models from hubs, external fine-tuning services. Each hand-off is a point where an artifact can be modified, substituted or poisoned. Traditional software supply-chain controls (code signing, SBOMs, SLSA) cover source and binaries, but an AI model's behaviour is determined by data and a non-reproducible training process, which those controls do not capture.

[Add 2–3 sentences on a real incident class: malicious pickle models on public hubs, poisoned web-scale datasets — cite from the state-of-the-art note.]

## 2. Problem statement

> How can an enterprise cryptographically verify that an AI model has not been tampered with at any stage of its supply chain, from data collection through pretrained base model acquisition to fine-tuning and deployment?

Two sub-questions structure the work:

1. **Integrity:** can we detect any modification, substitution or re-linking of an artifact after a trusted party attested it?
2. **Trust boundary:** what remains unprotected, in particular malicious content introduced *before* attestation, and what non-cryptographic evidence can narrow that gap?

## 3. Objectives and success criteria

| Objective | Success criterion (measurable) |
| --- | --- |
| Attest artifacts across ≥ 3 stages (target 4) | Datasets, base model, fine-tuned model and deployment record signed and hash-linked |
| Detect post-attestation tampering | Scenarios A–D: 100 % of variants FAILED, controls VERIFIED |
| Demonstrate the limit of attestation | Scenario E: signed poisoned data verifies; ASR reported |
| Keep the cost negligible | Attestation < 5 % of training time; verification < 100 ms for the demo chain |
| Reproducible prototype | `docker compose up` and CI gate pass on a clean machine |

## 4. Scope

**In scope:** SHA-256 hashing, Ed25519 signatures, JSON manifests, hash-linked provenance and dataset Merkle trees, signer roles and policy, revocation, a deployment gateway, a small PyTorch pipeline, five attack scenarios, a FastAPI backend, a Streamlit dashboard, Docker and GitHub Actions.

**Out of scope (discussed, not built):** blockchain anchoring, hardware attestation (TEEs), HSM/KMS key storage, reproducible training, large models, production authentication, full backdoor-detection research.

## 5. Approach

[One paragraph + the lifecycle diagram from `05_architecture.md`.] MVP by week 2 (register → hash → sign → verify → detect tampering), full four-stage chain by week 4, attacks and measurements in weeks 5–7, report in week 8.

## 6. Deliverables

Working prototype (repository), state-of-the-art analysis and comparative table, threat model, architecture and technical documentation, experimentation journal, ~30-page final report, live demonstration, conference proposal.

## 7. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Integration left too late | End-to-end MVP at week 2; CI runs the full chain on every push |
| Over-claiming security | Integrity vs semantic trust kept separate in code (V9 = WARNING) and in writing |
| Backdoor experiment fails to produce a backdoor | Small dataset, known BadNets setup, measured ASR from week 6 |
| Team member unavailable | Every security-critical file has a second reviewer |

## 8. Team and roles

| Member | Ownership |
| --- | --- |
| Karan DESHMUKH | Technical Lead / Security Architecture: architecture, integration, FastAPI backend, provenance design, deployment verification, coordination |
| JOGI Sudheer reddy | AI / ML Engineer: dataset preparation, PyTorch training and fine-tuning, poisoning and backdoor experiments, ML evaluation |
| DAMA Dola Krishna | Testing / Documentation / Quality Engineer: test scenarios, experimentation journal, results collection, quality assurance, dashboard support, weekly reports |
| MEKALA Rambabu | Security / DevOps Engineer: hashing, digital signatures, key handling, cryptographic verification, Docker, CI/CD |

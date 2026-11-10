# Scoping note: AI-ChainGuard

*Phase 1 deliverable of Projet Applicatif 2, "AI Supply Chain Integrity Platform" (ESAIP Master 1, referent Sofiane HAMRIOUI). Written in weeks 1 and 2 (from 21 September 2026); wording finalised on 10 November 2026 without changing the scope. Owner: Karan DESHMUKH.*

**Team:** Karan DESHMUKH, JOGI Sudheer reddy, DAMA Dola Krishna, MEKALA Rambabu. **Programme:** ESAIP Master 1, Cybersecurity and Data Science. **Duration:** 8 weeks.

## 1. Context and stakes

Enterprises increasingly assemble AI systems from parts they did not create: public datasets, pretrained models from hubs and external fine-tuning services. Each hand-off is a point where an artifact can be modified, substituted or poisoned. Traditional software supply-chain controls (code signing, SBOMs, SLSA) cover source code and binaries, but an AI model's behaviour is determined by data and by a training process that is rarely reproducible, and those controls do not capture that lineage.

The threat is concrete. In December 2022 a dependency-confusion attack replaced `torchtriton` in the PyTorch nightly builds with a package that stole SSH keys and files. In February 2024 JFrog found about one hundred models on Hugging Face whose pickle files ran code as soon as they were loaded. Web-scale training datasets have been shown to be poisonable for a few tens of dollars, and in 2025 about 250 poisoned documents were enough to plant a backdoor in language models from 600 million to 13 billion parameters (references in `02_state_of_the_art.md`). Regulation follows: Article 15(5) of the EU AI Act requires measures against data poisoning and model poisoning.

The stakes for an enterprise are the integrity of the models it deploys, its ability to show where a model came from after an incident, and a correct understanding of what a signed model does and does not guarantee.

## 2. Problem statement

> How can an enterprise cryptographically verify that an AI model has not been tampered with at any stage of its supply chain, from data collection through pretrained base model acquisition to fine-tuning and deployment?

Two sub-questions structure the work:

1. **Integrity:** can we detect any modification, substitution or re-linking of an artifact after a trusted party attested it?
2. **Trust boundary:** what remains unprotected, in particular malicious content introduced *before* attestation, and what non-cryptographic evidence can narrow that gap?

## 3. Assets

| Asset | Why it matters |
| --- | --- |
| Datasets (training and fine-tuning) | They determine model behaviour; the main target of poisoning |
| Pretrained base models | Downloaded from third parties; may carry a backdoor or executable code |
| Fine-tuned model weights | The behaviour that is deployed |
| Training and fine-tuning scripts, parameters and environment | Define how weights are produced; a compromised script or host alters the result |
| Inference and verification APIs, deployment configuration | Serve the deployed model and decide what is trusted |
| Signing keys, trust store and policy | Decide which signatures count; their theft defeats the scheme |
| Signed manifests, provenance graph and audit trail | The evidence used at deployment and after an incident |

## 4. Threats

| Threat | Example | Stage |
| --- | --- | --- |
| Data poisoning | Rows with a trigger pattern and a chosen label added to a dataset | Collection, before signing |
| Backdoor injection | A pretrained model whose weights react to a trigger, or a pickle file that runs code on load | Base-model acquisition |
| Model substitution | A signed model file replaced by a tampered or different one in storage | Storage, deployment |
| Pipeline compromise | A training host that alters weights, a poisoned dependency, a stolen or misused key, a rewritten provenance history | Training, fine-tuning, registry |
| Trust and revocation bypass | Clearing a revocation in the database, editing or truncating the audit log | Registry operations |

The full analysis (actors, trust boundaries, STRIDE classes and residual risks) is in `04_threat_model.md`.

## 5. Objectives and success criteria

| Objective | Success criterion (measurable) |
| --- | --- |
| Attest artifacts across at least 3 stages (target 4) | Datasets, base model, fine-tuned model and deployment record signed and hash-linked |
| Detect post-attestation tampering | Every tampering, substitution, provenance and signature variant FAILED; controls VERIFIED |
| Demonstrate the limit of attestation | Signed poisoned data verifies; backdoor success rate reported |
| Keep the cost negligible | Attestation under 5 % of training time; verification under 100 ms for the demo chain |
| Reproducible system | `docker compose up` and the CI gate pass on a clean machine |

## 6. Scope

**In scope:** SHA-256 hashing, Ed25519 signatures, JSON manifests, hash-linked provenance and dataset Merkle trees, signer roles and policy, revocation, a deployment gateway, a small PyTorch pipeline, attack scenarios and measurements, a FastAPI backend, a Streamlit dashboard, Docker and GitHub Actions.

**Out of scope (discussed, not built):** blockchain anchoring, hardware attestation (TEEs), HSM or KMS key storage, reproducible training, large models, production authentication for the API, research on new backdoor detectors.

## 7. Assumptions

- The signing keys, the policy file and the verifier code are trusted; everything else (files, storage, database, logs) may be attacked.
- Each role (data steward, training pipeline, release manager, deployment gateway, external publisher) has its own key.
- The test split used for evaluation is held out and trusted.
- A small model on the scikit-learn digits dataset is enough to measure integrity guarantees and the effect of a backdoor; the mechanisms do not depend on model size.

## 8. Constraints

- Eight weeks, four students, no budget: open-source tools only, CPU-only training.
- Every result must be reproducible from the repository (scripts, seeds, logs).
- Clear separation between what the cryptography proves and what it cannot prove, in the code and in the writing.

## 9. Limits

- A signature cannot prove that signed content is benign; poison present before signing is out of reach of integrity checks by design, and the project measures that limit instead of hiding it.
- Content checks are heuristics: they give evidence, not proof, and an adaptive attacker can evade them.
- Keys are stored as files for the demonstration; a production deployment would use a KMS or HSM and a shared transparency log.

## 10. Approach and plan

An end-to-end minimum viable chain first (register, hash, sign, verify, detect tampering), then the four-stage chain with roles, policy and revocation, then attacks and measurements, then the report. Planned milestones: minimum chain by week 2, full four-stage chain by week 4, attack scenarios and measurements in weeks 5 to 7, report, paper and demonstration in week 8. The lifecycle diagram is in `05_architecture.md`.

## 11. Deliverables

Working system (repository), state-of-the-art synthesis and comparative table, threat model, architecture and functional and technical descriptions, attack scenarios, experimentation journal, final report, live demonstration, conference proposal (`13_conference_proposal.md`) and the IEEE paper (`paper/`).

## 12. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Integration left too late | End-to-end chain at week 2; CI runs the full chain on every push |
| Over-claiming security | Integrity and semantic evidence kept separate in code (V9 gives WARNING) and in writing |
| Backdoor experiment fails to produce a backdoor | Small dataset, known BadNets setup, measured attack success rate |
| Team member unavailable | Every security-critical file has a second reviewer |

## 13. Team and roles

| Member | Ownership |
| --- | --- |
| Karan DESHMUKH | Technical lead and security architecture: architecture, integration, FastAPI backend, provenance design, deployment verification, coordination |
| JOGI Sudheer reddy | AI and ML engineering: dataset preparation, PyTorch training and fine-tuning, poisoning and backdoor experiments, ML evaluation |
| DAMA Dola Krishna | Testing, documentation and quality: test scenarios, experimentation journal, results collection, quality assurance, dashboard support, weekly reports |
| MEKALA Rambabu | Security and DevOps: hashing, digital signatures, key handling, cryptographic verification, Docker, CI/CD |

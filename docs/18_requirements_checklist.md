# Requirements checklist

*Every requirement of the brief "Quatre projets applicatifs IA" (ESAIP Master 1 MSc, referent Sofiane HAMRIOUI) that applies to Projet Applicatif 2, "AI Supply Chain Integrity Platform", with the evidence in this repository. Checked on 10 November 2026.*

Status: **Done**, **Done (email)** when the evidence was sent to the referent rather than committed, **Open** when something is still missing.

## Common framework for all projects

| Requirement | Evidence | Status |
| --- | --- | --- |
| Project over 2 months (8 weeks) | Week 1 from 21 September 2026; final presentation on 10 November 2026 | Done |
| Detailed weekly progress report to the referent (work done, difficulties, next steps) | Sent by email each week; template `10_weekly_report_template.md`; progress updates `14_progress_update_since_oct5.md` and `16_progress_update_v0.4.md` | Done (email) |
| Final presentation with a demonstration of the realisation | `17_presentation_guide.md`, `15_professor_demo_10min.md` (one command, 15 steps), `12_demo_scenario.md`; live website (signed model verified and run in the browser, in-browser chain demo with 10 attacks); dashboard (`make standalone`); CLI demo (`python -m scripts.demo`) | Done |
| Conference proposal: title, abstract, targeted venue | `13_conference_proposal.md` and the six-page IEEE paper in English and French (`paper/`) | Done |

## Pedagogical objectives

| Objective | Evidence | Status |
| --- | --- | --- |
| Understand AI-specific supply-chain threats (data poisoning, backdoored base models, environment poisoning) | `02_state_of_the_art.md` §2, `04_threat_model.md` | Done |
| Analyse risks for model provenance, dataset lineage and pipeline integrity | `04_threat_model.md` (assets, actors, trust boundaries, STRIDE, residual risks) | Done |
| Study cryptographic signing, hash chains and Merkle trees | `02_state_of_the_art.md` §3–4, `07_technical_description.md` | Done |
| Design a coherent attestation architecture | `05_architecture.md`, `06_functional_description.md`, `07_technical_description.md` | Done |
| Implement a functional system | `chainguard/`, `ml_pipeline/`, `deployment/`, `api/`, `dashboard/`, `cli/`; 168 tests; two GitHub Actions workflows passing | Done |
| Evaluate results objectively | `results/`, `08_attack_scenarios.md`, paper §V–VI, including the measured limit (signed poison verifies) | Done |

## Phase 1: scoping and problem definition

| Requirement | Evidence | Status |
| --- | --- | --- |
| Scope for AI artifact attestation in an enterprise context | `01_scoping_note.md` §1, §6 | Done |
| Assets: datasets, pretrained models, fine-tuned weights, training scripts, inference APIs | `01_scoping_note.md` §3, `04_threat_model.md` §1 | Done |
| Threats: data poisoning, backdoor injection, model substitution, pipeline compromise | `01_scoping_note.md` §4, `04_threat_model.md` | Done |
| A clear cybersecurity problem | `01_scoping_note.md` §2 | Done |
| Deliverable: scoping note (2–3 pages) | `01_scoping_note.md` | Done |

## Phase 2: state of the art and critical analysis

| Requirement | Evidence | Status |
| --- | --- | --- |
| AI supply-chain attacks: direct poisoning, pre-backdoored base models, environment poisoning | `02_state_of_the_art.md` §2.1–2.3 | Done |
| Existing solutions: cryptographic signing, SLSA for ML, model cards, Sigstore | `02_state_of_the_art.md` §3–5 | Done |
| Compare open-source, industrial and academic approaches | `02_state_of_the_art.md` §8, `03_comparative_table.md` | Done |
| Identify limitations | `02_state_of_the_art.md` §9 | Done |
| Deliverables: synthesis (3–5 pages), comparative table, argued justification of the approach | `02_state_of_the_art.md` (with §10 justification), `03_comparative_table.md` | Done |

## Phase 3: solution design

| Requirement | Evidence | Status |
| --- | --- | --- |
| Provenance and integrity architecture for AI artifacts | `05_architecture.md` | Done |
| Signing, verification and revocation mechanisms | `07_technical_description.md`, `05_architecture.md` §3–4; signed trust log in `chainguard/trustlog.py` | Done |
| Justified technical choices | `05_architecture.md` §7, `02_state_of_the_art.md` §10 | Done |
| Deliverables: architecture diagrams, functional and technical description, attack scenarios | `05_architecture.md` (six diagrams), `06_functional_description.md`, `07_technical_description.md`, `08_attack_scenarios.md` | Done |
| Indicative architecture: hash chain or Merkle tree | Hash-linked manifests (parent digests) and RFC 6962 dataset Merkle roots | Done |
| Indicative architecture: signing of models and datasets at each pipeline stage | Ed25519 manifests for datasets, base model, fine-tuned model and deployment record | Done |
| Indicative architecture: blockchain anchoring (optional) | Not built; replaced by a signed, hash-chained, pinned trust log, justified in `02_state_of_the_art.md` §4 and §10 | Optional, not built |
| Indicative architecture: CI/CD integration for automated attestation | `.github/workflows/attest-and-verify.yml` attests and verifies the chain on every push | Done |
| Indicative architecture: verification API for deployment gateways | `api/` (FastAPI) and `deployment/gateway.py` | Done |

## Phase 4: implementation and experimentation

| Requirement | Evidence | Status |
| --- | --- | --- |
| Simulated ML pipeline | `ml_pipeline/` (PyTorch CNN on the UCI digits, training and fine-tuning) | Done |
| Attestation across at least three pipeline stages | Four: datasets, base model, fine-tuned model, deployment record | Done |
| Documented code and scripts | `README.md`, module docstrings, `scripts/`, `07_technical_description.md` | Done |
| Test environment description | `09_experimentation_journal.md` (setup of each run), `README.md`, website footer; reference environment of 9 November 2026 | Done |
| Experimentation journal | `09_experimentation_journal.md` | Done |
| Technologies: Python, PyTorch | Python 3.11–3.13, PyTorch | Done |
| Technologies: Sigstore, cosign or custom signing with OpenSSL | Custom Ed25519 signing (`cryptography`, OpenSSL backend); optional Sigstore keyless job in CI (off by default) | Done |
| Technologies: Merkle tree library | Own RFC 6962 implementation (`chainguard/provenance/merkle.py`) | Done |
| Technologies: Docker, GitHub Actions | `docker/`, `.github/workflows/` (both workflows passing) | Done |
| Technologies: Hyperledger Fabric (optional) | Not used; see the trust-log justification | Optional, not built |

## Phase 5: testing, evaluation and critical analysis

| Requirement | Evidence | Status |
| --- | --- | --- |
| Test against realistic attack scenarios | 48 attack and control variants in seven experiments, `python -m attacks.run_all`, `08_attack_scenarios.md` | Done |
| Measure detection rates and overhead | Every post-signing manipulation detected in 1.7–15.1 ms; attestation 0.8 % of training time; 8.5 ms per full-chain verification; nothing per inference; `results/` | Done |
| Deliverables: test results (logs, tables, graphs) | `results/attacks/*.json`, `results/attacks/summary.csv`, `results/validation_logs/`, `results/figures/`, paper figures, website charts | Done |
| Critical analysis of security guarantees and limitations | Paper §VI, `04_threat_model.md` (residual risks), website sections "What a signature proves, and what it does not" and "Limits" | Done |
| Improvement paths | Paper conclusion and future work, `11_final_report_structure.md` §9, `08_attack_scenarios.md` | Done |
| Example: inject a backdoor into a fine-tuning dataset and verify detection failure or success | E2–E4 (poison in the training set: VERIFIED and deployed at 77.2 %; content checks give WARNING; adaptive trigger 51.2 %) and the supplementary FT-E2/FT-E3 run with the poison in the fine-tuning set (VERIFIED, deployed, 25.3 %; WARNING, blocked), `results/attacks/e2_finetune_poison.json` | Done |
| Example: substitute a signed model with a tampered version | Scenario B: control VERIFIED, 3 variants FAILED (V1) | Done |
| Example: verify provenance of a model from an untrusted repository | Scenario G / Experiment 7: 9 variants (trusted, unknown and unsigned publishers; REFUSED at import, FAILED, or VERIFIED for a trusted publisher) | Done |
| Example: measure attestation overhead on training and inference | 0.8 % of training time; inference 0.084 ms before and 0.085 ms after the verified deployment | Done |

## Phase 6: reporting and valorisation

| Requirement | Evidence | Status |
| --- | --- | --- |
| Final report (about 30 pages) | Content written in documents 01 to 09, the paper and `results/`; structure in `11_final_report_structure.md`; not yet assembled into one document | **Open** |
| Oral defence | 10 November 2026; `17_presentation_guide.md` | Done |
| Demonstration or use case | See the common framework above | Done |
| Conference proposal | `13_conference_proposal.md`, `paper/` | Done |

## Expected results

| Expected result | Evidence | Status |
| --- | --- | --- |
| A functional AI supply-chain attestation system | The repository; CI attests, verifies and deploys the chain on every push; the website verifies and runs the signed model in the browser | Done |
| A complete engineering approach with threat modelling | Documents 01 to 09, `04_threat_model.md` | Done |
| Critical analysis of results | Paper §V–VI; the measured boundary between integrity and semantic trust | Done |
| Work that can be valorised in an enterprise security context | Conference paper in English and French; in-toto/DSSE and SLSA export; deployment gateway | Done |

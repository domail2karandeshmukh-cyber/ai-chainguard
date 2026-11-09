# AI-ChainGuard: AI Supply Chain Integrity & Attestation Platform

ESAIP Master 1 MSc · Projet Applicatif 2 · Applied AI Projects · Referent: Sofiane HAMRIOUI
Team: Karan DESHMUKH, JOGI Sudheer reddy, DAMA Dola Krishna, MEKALA Rambabu
**Version 0.3 (16 October 2026)**. What changed since 5 October: [`docs/14_progress_update_since_oct5.md`](docs/14_progress_update_since_oct5.md)

## What AI-ChainGuard is

AI-ChainGuard turns every AI artifact into a **signed, hash-linked manifest**. Covered artifacts:

- datasets;
- internally trained base models;
- base models published by an outside party;
- fine-tuned models;
- deployment records.

Before a model is loaded, a **deployment gateway** verifies the whole chain and decides to approve, warn or block. All security logic lives in one library (`chainguard/`), shared by the CLI, the REST API, the ML pipeline, the gateway and CI.

## Security guarantee

**VERIFIED** means the artifact is exactly what a trusted, unrevoked signer in an authorised role attested, through an intact chain of ancestors. Concretely:

- the file bytes match the signed SHA-256 (and, for datasets, the signed row-level Merkle root);
- the signature is valid Ed25519 over the whole manifest (type, stage, parents, signer role), not only the file hash;
- every parent link matches the parent's manifest digest, recursively;
- no artifact or key in the chain is revoked;
- the supply-chain policy is respected (who may sign which stage, which parents are required).

Ten checks (V0–V9) run at every verification:

| ID | Check | Fails when |
| --- | --- | --- |
| V0 | Envelope | missing, invalid JSON, schema error, envelope stored under another id |
| V1 | File hash | SHA-256 or size differs from the signed values |
| V2 | Dataset Merkle root | rows changed (the report lists which lines) |
| V3 | Ed25519 signature | invalid over the canonical payload, or unknown key |
| V4 | Signer trust | key revoked, role/identity mismatch, role not allowed for the stage |
| V5 | Parent links | parent missing or its manifest digest changed |
| V6 | Ancestry | any ancestor FAILED (recursive) |
| V7 | Revocation | artifact or ancestor revoked, or index row deleted |
| V8 | Policy | wrong type for stage, missing/forbidden parent types, wrong stage order |
| V9 | Semantic flags | a signed content check flagged data here or upstream → **WARNING only** |

## What it does NOT guarantee

- **It does not prove a model is safe.** A dataset poisoned *before* signing verifies perfectly: Scenario E2 deploys a backdoored model with a 77 % attack success rate. A trusted outside publisher can sign a backdoored model, and it verifies (Experiment 7, E7-F: 100 % attack success rate).
- **Content checks are heuristics.** They only ever raise WARNING, and an adaptive trigger evades them (E4).
- **A stolen, unrevoked key produces valid signatures.**
- **Revocation state lives in the trusted SQLite index.** Editing it directly undoes a revocation (Experiment 5, E5-C4).
- **It is a prototype:** file-based keys, no API authentication, no TLS.

## Architecture

```
 data source ──► [stage 1] dataset ───────────► signed by data_steward     (Merkle root + content checks)
                        │
                        ▼
                 [stage 2] base_model ─────────► signed by training_pipeline (parent: dataset, REQUIRED)
 outside publisher ─► [stage 2 ext] external_base_model ─► signed by model_publisher (public key registered;
                        │                                   no internal lineage)
                        ▼
                 [stage 3] finetuned_model ────► signed by training_pipeline (parents: dataset + one base model)
                        │
                        ▼
                 [stage 4] deployment gateway ─► verifies V0-V9 once, safe load, smoke test,
                                                 signed deployment_record (deployment_gateway)
```

Trusted components: signing keys, the trust store and policy, and the verifier. Treated as hostile: artifact storage, datasets, external model repositories, training hosts and the network. The verifier therefore recomputes every hash and digest instead of trusting stored values. The full design is in [`docs/05_architecture.md`](docs/05_architecture.md) and [`docs/07_technical_description.md`](docs/07_technical_description.md); the external-model design is in [`chainguard/external.py`](chainguard/external.py).

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate         # Windows: .venv\Scripts\activate
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements-dev.txt
python -m scripts.demo                                     # the 10-minute demo (pauses between steps)
```

## Local setup

Python 3.11 or newer is required (validated on 3.13; CI uses 3.11). No GPU is needed.

```bash
export CHAINGUARD_HOME=$PWD          # Windows PowerShell: $env:CHAINGUARD_HOME = (Get-Location)
python -m cli.main keys init         # one Ed25519 key pair per internal role -> keys/*.pem (0600, git-ignored)
python -m cli.main mvp-demo          # register -> VERIFIED -> tamper one label -> FAILED
python -m ml_pipeline.run_pipeline   # 4 attested stages + deployment gateway (~5 s on CPU)
```

API and dashboard, in two terminals:

```bash
uvicorn api.main:create_app --factory --port 8000      # http://localhost:8000/docs
streamlit run dashboard/Overview.py                    # http://localhost:8501
```

`make help` lists the same commands as Make targets.

## Docker setup

**Status: IMPLEMENTED / STATICALLY REVIEWED / LOCAL EXECUTION REQUIRED.** The team has not executed it yet.

```bash
docker compose -f docker/docker-compose.yml up --build
```

Expected output:

1. The image builds; the first build downloads CPU PyTorch and takes a few minutes.
2. `pipeline` prints `[stage 1]` … `[stage 4] gateway: VERIFIED -> DEPLOYED` and exits with code 0.
3. `api` becomes healthy (`Uvicorn running on http://0.0.0.0:8000`).
4. `dashboard` starts.
5. Open http://localhost:8000/docs and http://localhost:8501.

Optional, after the stack has been up once:

```bash
docker compose -f docker/docker-compose.yml --profile experiments run --rm experiments   # attacks A-G
docker compose -f docker/docker-compose.yml --profile demo run --rm demo                 # demo, no pauses
docker compose -f docker/docker-compose.yml down                                         # add -v to wipe the workspace volume
```

## Tests

```bash
ruff check .
pytest -q                     # 143 tests (pytest -q -m "not slow" skips the backdoor training test)
```

Last run (reference environment, 16 Oct 2026): **143 passed, 0 failed, 0 skipped, 32 s.** The 5 October baseline had 113. Logs are in [`results/validation_logs/`](results/validation_logs/).

## Experiments

```bash
python -m attacks.run_all            # scenarios A-G; results in results/attacks/
python -m attacks.run_all --only G   # one scenario
python -m scripts.benchmark --machine-label "team laptop - <owner>, <cpu>"   # crypto + inference + manifest sizes
python -m scripts.make_figures       # figures in results/figures/
```

| Experiment | Scenario | What it shows |
| --- | --- | --- |
| 1 Dataset tampering | A | any post-signing change detected and localised to the line (V1, V2); descendants fail (V6) |
| 2 Model substitution | B | replaced, nudged (1e-6) or re-pickled weights fail (V1); gateway blocks |
| 3 Invalid signature | D | corrupted, replayed, unknown-key, revoked-key, wrong-role signatures fail (V3/V4) |
| 4 Broken provenance | C | deleted parent, re-signed parent, edited link, missing dataset parent fail (V5/V3/V8) |
| 5 Revocation (v0.3) | F | revoked artifact or key fails its descendants and blocks deployment; index-deletion bypasses fail closed; **E5-C4 limitation** |
| 6 Poisoned before signing | E | the limitation: signed poison verifies and deploys (E2); content checks catch a known trigger (E3) but not an adaptive one (E4) |
| 7 Untrusted external source (v0.3) | G | trusted publisher → VERIFIED (labelled external); unknown publisher, modified bytes, revoked publisher key → FAILED; unsigned → REFUSED; **E7-F limitation** |

Details: [`docs/08_attack_scenarios.md`](docs/08_attack_scenarios.md).

### External models from the command line (Experiment 7)

```bash
python -m cli.main publisher keygen pub/                                   # the outside publisher (simulated)
python -m cli.main publisher sign model.safetensors --key pub/publisher.pem --identity bot@hub.example
python -m cli.main keys trust-publisher pub/publisher.pub --identity bot@hub.example   # our trust decision
python -m cli.main import-external model.safetensors --manifest model.safetensors.manifest.json
```

## 10-Minute Professor Demo

```bash
python -m scripts.demo          # or: make demo        (rehearsal without pauses: python -m scripts.demo --auto)
```

It runs 13 steps in a throw-away `demo-ws/` workspace, pausing at each one with a one-line talking point:

1. clean supply chain
2. verify the final model
3. VERIFIED
4. provenance tree
5. tamper with the training dataset
6. verify again
7. FAILED
8. gateway BLOCKED
9. invalid signature
10. revocation
11. poisoned-before-signing limitation
12. trusted vs untrusted external model
13. live metrics

Runbook, timings and likely questions: [`docs/15_professor_demo_10min.md`](docs/15_professor_demo_10min.md).

## Current results

AI-assisted reference environment (cloud Linux container, 2 vCPU Xeon, CPU only), 16 October 2026. **Not yet reproduced on team hardware.** The 5 October results are archived in `results/archive_2026-10-05_baseline/`.

- **Attacks:** 44 / 44 variants end with the expected status ([table](results/figures/attack_table.md), `results/attacks/summary.csv`).
- **Pipeline:** clean test accuracy 95.0 %. Attestation of 4 artifacts took 10.8 ms vs 1,261 ms of training (0.86 %, small CPU model, workload-dependent). Gateway chain verification took 8.9 ms.
- **Inference** (median, `results/metrics/inference_benchmark.csv`):
  - one prediction: 0.080 ms before and 0.080 ms after verified deployment, so no per-prediction cost;
  - full chain verification: 7.95 ms;
  - first secure deployment through the gateway: 235 ms, once per deployment (mostly SQLite audit writes plus a second chain verification).
- **Manifest sizes:** signed envelopes are 1.4–3.1 KB per artifact; dataset Merkle sidecars are 30–68 KB (`results/metrics/manifest_sizes.csv`).
- **Hashing and signatures:** SHA-256 runs at about 1.1–1.2 GB/s. Ed25519 signing takes 0.03–0.06 ms and verification 0.11–0.20 ms, independent of artifact size.
- **Backdoor (E):** clean model ASR 0 %; signed poison (E2) deploys with 94.2 % clean accuracy and 77.2 % ASR; the adaptive trigger (E4) deploys with 51.2 % ASR.

Figures: `results/figures/`, including the new `fig_inference_overhead.png`.

## Current project status

| Area | Status |
| --- | --- |
| Core (hashing, signing, manifests, provenance, Merkle, V0–V9, registry, revocation) | Completed, tested |
| Pipeline (4 stages) and deployment gateway | Completed, tested |
| External published models (Experiment 7) | Completed in v0.3, tested (CLI and library; no API/dashboard import view yet) |
| Revocation experiment (Experiment 5) | Completed in v0.3, tested |
| Inference-overhead benchmark, manifest sizes | Completed in v0.3 (reference environment only) |
| API, dashboard, CLI | Prototype, no authentication |
| Docker | Implemented / statically reviewed / **local execution required** |
| GitHub Actions | Implemented, **not yet executed** (no repository yet); steps reproduced locally |
| Results on team hardware | **Not yet done** |
| State of the art | Draft; references still to verify |

## Team

| Member | Role | Ownership |
| --- | --- | --- |
| Karan DESHMUKH | Technical Lead / Security Architecture | Architecture, integration, FastAPI backend, provenance design, deployment verification, coordination |
| JOGI Sudheer reddy | AI / ML Engineer | Dataset preparation, PyTorch training and fine-tuning, poisoning and backdoor experiments, ML evaluation |
| DAMA Dola Krishna | Testing / Documentation / Quality Engineer | Test scenarios, experimentation journal, results collection, quality assurance, dashboard support, weekly reports |
| MEKALA Rambabu | Security / DevOps Engineer | Hashing, digital signatures, key handling, cryptographic verification, Docker, CI/CD |

The prototype was developed with AI-assisted code generation and validated by execution. Team code walkthroughs and reproduction on team hardware are planned.

## Known limitations

| Prototype | Production |
| --- | --- |
| Private keys as 0600 files or CI secrets | HSM / cloud KMS, or keyless Sigstore (Fulcio + Rekor) |
| Trust store and revocation in SQLite (E5-C4: editing the index undoes a revocation) | signed, pinned trust root; append-only revocation list / transparency log |
| Publisher trust is a manual, out-of-band registration of a public key | identity-based policies (Sigstore / OpenSSF model signing) |
| Canonical JSON (sorted keys, compact) | RFC 8785 JCS for cross-language signers |
| API without authentication or TLS | mTLS / OIDC, per-role authorisation, keys never on the API host |
| Builder environment is a signed *claim* | hardware attestation (TEE) or reproducible builds |
| Heuristic semantic checks (corner trigger, label drift) | trigger-agnostic defences, evaluation suites; a signature never proves safety |
| Gateway verifies the chain twice on first deployment | single verification reused for the deployment record |
| `/demo/*` endpoints that tamper on purpose | disabled (`CHAINGUARD_DEMO_MODE=0`) |

## Next work

1. Create the GitHub repository; record the first runs of both workflows.
2. Run the Docker stack on a team machine.
3. Re-run tests, pipeline, attacks and benchmark on team hardware (`--machine-label`); write a journal entry.
4. Code walkthroughs by module owner.
5. Experiment 7 follow-up: Sigstore / OpenSSF interoperability decision; API endpoint and dashboard view for external imports.
6. Signed revocation list to close E5-C4.
7. State of the art with every reference verified.

## Repository map

```
chainguard/        core library: crypto, manifest, provenance, semantic, verification, storage,
                   trust (roles incl. model_publisher), external.py (v0.3 external models)
cli/               Typer CLI (keys, register, verify, revoke, list, events, mvp-demo,
                   publisher keygen/sign, keys trust-publisher, import-external)
api/               FastAPI backend (thin layer over chainguard)
ml_pipeline/       PyTorch pipeline: dataset export, CNN, training, fine-tuning, evaluation, run_pipeline
deployment/        Stage 4 deployment gateway
attacks/           Scenarios A-G + run_all
dashboard/         Streamlit dashboard (talks to the API only)
tests/             unit + integration tests (143)
config/policy.yaml who may sign what, required/allowed parents
docker/            Dockerfile + compose (profiles: experiments, demo)
.github/workflows/ CI (lint, tests) and attest-and-verify gate
scripts/           benchmark, inference_benchmark, make_figures, demo
results/           metrics, attack results, figures, validation logs, 5 Oct archive
docs/              scoping note ... conference proposal; 14 progress update; 15 demo runbook
```

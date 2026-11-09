# AI-ChainGuard: AI Supply Chain Integrity & Attestation Platform

ESAIP Master 1 MSc · Projet Applicatif 2 · Applied AI Projects · Referent: Sofiane HAMRIOUI
Team: Karan DESHMUKH, JOGI Sudheer reddy, DAMA Dola Krishna, MEKALA Rambabu
**Version 0.4 (9 November 2026)**. What changed: [`docs/16_progress_update_v0.4.md`](docs/16_progress_update_v0.4.md) · v0.3 notes: [`docs/14_progress_update_since_oct5.md`](docs/14_progress_update_since_oct5.md) · IEEE paper: [`paper/signed_is_not_safe.pdf`](paper/signed_is_not_safe.pdf) (English) · [`paper/signed_is_not_safe_fr.pdf`](paper/signed_is_not_safe_fr.pdf) (French)

> **One sentence.** Existing tools sign one artifact (cosign, OpenSSF Model Signing), describe it (model cards, ML-BOM) or attest software builds (SLSA, in-toto). AI-ChainGuard links datasets, base models, fine-tuned models and deployments into **one verifiable chain with a role policy, a signed revocation log and a deployment gate**, exports to the ecosystem's formats (in-toto / DSSE / SLSA), and **measures** where cryptographic integrity stops: *a signed model is not a safe model*. Why that matters and how it compares: [`docs/03_comparative_table.md`](docs/03_comparative_table.md) and the dashboard page **Why ChainGuard**.

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
- no artifact or key in the chain is revoked **according to the signed, pinned, append-only trust log** (v0.4);
- the supply-chain policy is respected (who may sign which stage, which parents are required).

Ten checks (V0–V9) run at every verification:

| ID | Check | Fails when |
| --- | --- | --- |
| V0 | Envelope | missing, invalid JSON, schema error, envelope stored under another id |
| V1 | File hash | SHA-256 or size differs from the signed values |
| V2 | Dataset Merkle root | rows changed (the report lists which lines) |
| V3 | Ed25519 signature | invalid over the canonical payload, or key not in the signed trust log |
| V4 | Signer trust | key revoked, role/identity mismatch, role not allowed for the stage, or index and signed log disagree (index tampering) |
| V5 | Parent links | parent missing or its manifest digest changed |
| V6 | Ancestry | any ancestor FAILED (recursive) |
| V7 | Revocation | artifact or ancestor revoked in the signed trust log (or flagged in the index), index row deleted, or index flag cleared while the log says revoked |
| V8 | Policy | wrong type for stage, missing/forbidden parent types, wrong stage order |
| V9 | Semantic flags | a signed content check flagged data here or upstream → **WARNING only** |

## What it does NOT guarantee

- **It does not prove a model is safe.** A dataset poisoned *before* signing verifies perfectly: Scenario E2 deploys a backdoored model with a 77 % attack success rate. A trusted outside publisher can sign a backdoored model, and it verifies (Experiment 7, E7-F: 100 % attack success rate).
- **Content checks are heuristics.** They only ever raise WARNING, and an adaptive trigger evades them (E4).
- **A stolen, unrevoked key produces valid signatures.**
- **The keys directory is trusted.** The root private key and the pin `keys/trust_root.json` anchor the trust log; whoever controls them controls the trust decisions (Experiment 5 shows that controlling only the SQLite index or the log file is no longer enough).
- **Revocation is local.** The log is signed and portable but not yet published to a shared transparency log, so another verifier with a stale copy would not see a recent revocation.
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

```
 release_manager (root key) ─► artifacts/trust/trust_log.jsonl   signed, hash-chained, append-only records:
                                                                  trust_key · revoke_key · revoke_artifact · rotate_root
 keys/trust_root.json (pin)  ─► root public key + hash and sequence number of the last record
```

Trusted components: the signing keys (including the root key and the pin), the policy and the verifier. Treated as hostile: artifact storage, the SQLite index, datasets, external model repositories, training hosts and the network. The verifier therefore recomputes every hash and digest instead of trusting stored values, and since v0.4 replays the signed trust log instead of believing the index for keys and revocations (`chainguard/trustlog.py`). The full design is in [`docs/05_architecture.md`](docs/05_architecture.md) and [`docs/07_technical_description.md`](docs/07_technical_description.md); the external-model design is in [`chainguard/external.py`](chainguard/external.py).

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

**Status: EXECUTED ON TEAM HARDWARE (Karan's MacBook Air, 16 October 2026):** image build, Compose stack, four-stage pipeline (VERIFIED → DEPLOYED, clean accuracy 0.950), API `/health` 200 and dashboard on :8501. Docker is not available in the reference environment, so the v0.4 image has been built there only statically; rebuild it on a team machine after pulling v0.4.

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
pytest -q                     # 168 tests (pytest -q -m "not slow" skips the backdoor training test)
scripts/run_validation.sh "team laptop - <owner>, <cpu>"   # the whole validation sequence, logs in results/validation_logs/
```

Last run (reference environment, 9 Nov 2026): **168 passed, 0 failed, 0 skipped, 36 s.** v0.3 had 143 and the 5 October baseline 113. Logs are in [`results/validation_logs/`](results/validation_logs/); the v0.3 results are archived in `results/archive_2026-10-16_v0.3/`.

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
| 5 Revocation (v0.3, extended v0.4) | F | revoked artifact or key fails its descendants and blocks deployment; every index bypass (deleted rows, cached status, cleared flag, rogue key) and every attack on the signed log (truncate, edit, delete) fails closed - **E5-C4 closed in v0.4** |
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

### Signed trust log and interoperability (v0.4)

```bash
python -m cli.main keys trust-log                                        # replay the signed log against the pinned root
python -m cli.main export <ARTIFACT_ID> --format slsa --out model.slsa.json   # in-toto Statement (SLSA Provenance v1) in a DSSE envelope
python -m cli.main export <ARTIFACT_ID> --format intoto --unsigned           # bare Statement with the ChainGuard predicate
```

The same is available in the API (`GET /trust-log`, `GET /artifacts/{id}/attestation?format=slsa`) and the dashboard (**Trust Log** page with live sandboxed bypass attempts, **External Models** page with one-click publisher demos, **Why ChainGuard** comparison page). The dashboard also runs without a separate API process: `make standalone` (`CHAINGUARD_STANDALONE=1`).

## 10-Minute Professor Demo

```bash
python -m scripts.demo          # or: make demo        (rehearsal without pauses: python -m scripts.demo --auto)
```

It runs 15 steps in a throw-away `demo-ws/` workspace, pausing at each one with a one-line talking point:

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
11. attack the trust itself: edit the index, truncate the signed log → fails closed (v0.4)
12. poisoned-before-signing limitation
13. trusted vs untrusted external model
14. in-toto / DSSE export with SLSA provenance, verified (v0.4)
15. live metrics

Runbook, timings and likely questions: [`docs/15_professor_demo_10min.md`](docs/15_professor_demo_10min.md).

## Current results

AI-assisted reference environment (cloud Linux container, 2 vCPU Xeon @ 2.10 GHz, 8 GB, CPU only, Python 3.13, PyTorch 2.15), 9 November 2026. Docker Compose, the four-stage pipeline, the API health check and the dashboard were additionally executed on team hardware (Karan's MacBook Air) on 16 October 2026; tests and benchmarks have **not yet** been re-run on team hardware (`scripts/run_validation.sh` exists for that).

- **Attacks:** 48 / 48 variants end with the expected status ([table](results/figures/attack_table.md), `results/attacks/summary.csv`). Every manipulation made after signing is detected, including a 1e-6 weight nudge and one trailing space; the former limitation E5-C4 and the four new attacks on the trust log (E5-C5 to C8) all fail closed.
- **The boundary, measured:** signed poison deploys as VERIFIED with 94.2 % clean accuracy and 77.2 % backdoor success (E2); content checks raise WARNING for a known trigger (E3) and miss an adaptive one that still reaches 51.2 % (E4); a trusted publisher's backdoored model verifies with 100 % backdoor success (E7-F).
- **Pipeline:** clean test accuracy 95.0 %. Attestation of 4 artifacts took 10.7 ms vs 1,288 ms of training (0.83 %, small CPU model, workload-dependent).
- **Inference** (median, `results/metrics/inference_benchmark.csv`): one prediction 0.084 ms before and 0.085 ms after verified deployment (no per-prediction cost); full chain verification 8.5 ms (7.95 ms in v0.3; replaying the 5-record trust log costs 0.16 ms with cached signatures, 0.75 ms cold); first secure deployment through the gateway 253 ms, once per deployment.
- **Trust log** (`results/metrics/trustlog_benchmark.csv`): replaying 5 / 50 / 500 / 2 000 records costs 0.8 / 6.9 / 69 / 288 ms with every signature verified (about 0.14 ms per record, Ed25519-bound) and 0.16 / 0.8 / 7.7 / 31 ms with the per-process signature cache; a 2 000-record log is 0.8 MB.
- **Manifest sizes:** signed envelopes are 1.4–3.1 KB per artifact; dataset Merkle sidecars are 30–68 KB.
- **Hashing and signatures:** SHA-256 runs at about 1.2 GB/s from 1 MiB upwards; Ed25519 signing takes 0.04 ms and verification 0.12–0.14 ms, independent of artifact size.

Figures: `results/figures/` (`fig_attack_outcomes.png`, `fig_backdoor_asr.png`, `fig_inference_overhead.png`, ...) and the vector figures of the paper in `paper/figures/`.

## Current project status

| Area | Status |
| --- | --- |
| Core (hashing, signing, manifests, provenance, Merkle, V0–V9, registry, revocation) | Completed, tested |
| Signed, pinned, append-only trust log (v0.4) | Completed, tested (12 unit + 7 integration tests, Scenario F variants C4–C8); file-locked writes; `keys trust-log --repair` recovers a pin left behind by a crash |
| Pipeline (4 stages) and deployment gateway | Completed, tested; deployment record binds the trust-log head |
| External published models (Experiment 7) | Completed; CLI, library, **API and dashboard page (v0.4)** |
| Interoperability: in-toto Statement / DSSE / SLSA Provenance v1 export (v0.4) | Completed, tested (CLI, API) |
| Inference-overhead, manifest-size and trust-log benchmarks | Completed (reference environment only) |
| API, dashboard, CLI | Prototype, no authentication; dashboard runs standalone |
| Docker | Image build, Compose stack, pipeline, API and dashboard executed on team hardware (16 Oct 2026) |
| GitHub Actions | Implemented and statically checked, **not yet executed on GitHub** (no repository yet) |
| Tests and benchmarks on team hardware | **Not yet done** (`scripts/run_validation.sh`) |
| State of the art and IEEE paper | Paper drafted with verified references (`paper/`); SoA document still to consolidate |

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
| Trust log is local and single-writer (v0.4 closed E5-C4) | publish the records to a shared transparency log (Rekor-style) so every verifier sees one history |
| Publisher trust is a manual, out-of-band registration of a public key | identity-based policies (Sigstore / OpenSSF model signing) |
| Canonical JSON (sorted keys, compact) | RFC 8785 JCS for cross-language signers |
| API without authentication or TLS | mTLS / OIDC, per-role authorisation, keys never on the API host |
| Builder environment is a signed *claim* | hardware attestation (TEE) or reproducible builds |
| Heuristic semantic checks (corner trigger, label drift) | trigger-agnostic defences, evaluation suites; a signature never proves safety |
| Gateway verifies the chain twice on first deployment | single verification reused for the deployment record |
| `/demo/*` endpoints that tamper on purpose | disabled (`CHAINGUARD_DEMO_MODE=0`) |

## Next work

1. Create the GitHub repository; record the first runs of both workflows.
2. Re-run `scripts/run_validation.sh` on team hardware; write a journal entry.
3. Code walkthroughs by module owner.
4. Publish trust-log records to a shared transparency log; evaluate Sigstore keyless signing for the roles.
5. Consolidate the state-of-the-art document from the paper's reference list.

## Repository map

```
chainguard/        core library: crypto, manifest, provenance, semantic, verification, storage,
                   trust (roles incl. model_publisher), trustlog.py (v0.4 signed trust log),
                   external.py (v0.3 external models), interop.py (v0.4 in-toto/DSSE/SLSA export)
cli/               Typer CLI (keys init/list/revoke/trust-publisher/trust-log, register, verify, revoke,
                   list, events, export, mvp-demo, publisher keygen/sign, import-external)
api/               FastAPI backend (thin layer over chainguard)
ml_pipeline/       PyTorch pipeline: dataset export, CNN, training, fine-tuning, evaluation, run_pipeline
deployment/        Stage 4 deployment gateway
attacks/           Scenarios A-G + run_all
dashboard/         Streamlit dashboard (talks to the API; embeds it in standalone mode)
paper/             IEEE conference paper, English and French (LaTeX, vector figures regenerated from results/)
tests/             unit + integration tests (168)
config/policy.yaml who may sign what, required/allowed parents
docker/            Dockerfile + compose (profiles: experiments, demo)
.github/workflows/ CI (lint, tests) and attest-and-verify gate
scripts/           benchmark, inference_benchmark, trustlog_benchmark, make_figures, demo, run_validation.sh
results/           metrics, attack results, figures, validation logs, 5 Oct and 16 Oct archives
docs/              scoping note ... conference proposal; 14 (v0.3) and 16 (v0.4) progress updates; 15 demo runbook
```

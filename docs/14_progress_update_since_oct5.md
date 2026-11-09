# AI-ChainGuard — Progress Update Since 5 October 2026

*Version 0.3 · 16 October 2026 · ESAIP Master 1, Projet Applicatif 2 · Referent: Sofiane HAMRIOUI*

**Evidence rule (unchanged from the Week 1 report).** A feature is reported as completed only when code and repeatable execution evidence exist. Every number below comes from one run on **16 October 2026 in the AI-assisted reference development environment** (cloud Linux container, Intel Xeon @ 2.10 GHz, 2 logical CPUs, 7.8 GB RAM, Python 3.13.16, PyTorch 2.14.1 CPU execution). These numbers are **not yet reproduced on team hardware**. Raw logs: `results/validation_logs/`.

**Development note.** The v0.3 changes, like the 5 October prototype, were produced with AI-assisted code generation and validated by execution in the reference environment. Team walkthrough and reproduction remain planned.

## 1. Baseline on 5 October

The 5 October repository (v0.2 package) contained:

- A working core: SHA-256 hashing, Ed25519 signing, signed JSON manifests, hash-linked provenance, a dataset Merkle tree, the ten checks V0–V9, a SQLite registry with revocation and security events.
- A 4-stage PyTorch pipeline and a deployment gateway.
- FastAPI, a Streamlit dashboard and a CLI.
- Attack scenarios A–E (26 variants).
- 113 passing tests.

Pending at that date:

- Docker and CI were written but never executed.
- Experiment 7 (untrusted model source) had not been started.
- Experiment 5 (revocation) existed only as tests.
- Inference overhead was only partly measured.
- Manifest size was still "TO BE MEASURED".
- Team names in the repository were outdated.

The 5 October result files are preserved unchanged in `results/archive_2026-10-05_baseline/`.

## 2. Work completed in v0.3

| # | Item | Status |
|---|---|---|
| 1 | Team names corrected everywhere (README, pyproject, docs 01, 02, 10, 12); journal attribution corrected | Completed |
| 2 | Experiment 7: external published base models, `model_publisher` role, import path, scenario G, tests | Completed |
| 3 | Experiment 5: stand-alone revocation scenario F in the attack runner, tests | Completed |
| 4 | Inference-overhead benchmark (A–D), figure | Completed (reference environment only) |
| 5 | Manifest-size metric | Completed (reference environment only) |
| 6 | Full validation: ruff, pytest, pipeline, attacks, benchmark, figures | Completed (reference environment only) |
| 7 | Docker review and fixes | Implemented / statically reviewed / **local execution required** |
| 8 | GitHub Actions review and fixes | Implemented, **not yet executed** |
| 9 | This progress document | Completed |
| 10 | README rewrite | Completed |
| 11 | 10-minute professor demo (`python -m scripts.demo`, `docs/15_professor_demo_10min.md`) | Completed, runs in about 10 s of computation |

## 3. New technical functionality

**External models (Experiment 7).** New module `chainguard/external.py`.

- **New artifact type and stage:** `external_base_model` in a new stage `stage2_external_import`. It can be signed only by a `model_publisher` key.
- **Internal rule unchanged:** an internal `base_model` still requires a dataset parent. The roles are separated in both directions, so an internal model cannot be relabelled "external" to escape that rule.
- **Publisher keys:** we register only the publisher's *public* key (`TrustStore.trust_publisher`), and never generate or hold its private key.
- **Import refusals:** `import_external_model` stores nothing when the model is unsigned, has a malformed manifest, carries no signature, has the wrong type or stage, declares parents, uses a URI outside `artifacts/external/`, or is a duplicate.
- **Failed imports:** anything that fails verification is kept in the index as audit evidence (quarantined), but it cannot be used as a parent and cannot be deployed.
- **Labelling:** verification reports list the external artifacts in a chain (`external_artifacts`), and V8 states that provenance ends at the publisher.
- **Fine-tuning policy:** a fine-tuned model needs a dataset parent plus one base model of either kind (new `required_one_of` rule).
- **CLI:** `publisher keygen`, `publisher sign` (simulated publisher), `keys trust-publisher`, `import-external`.

**Revocation (Experiment 5).** `attacks/scenario_f_revocation.py` covers the control, artifact revocation, key revocation and four bypass attempts.

**Measurement.**

- `scripts/inference_benchmark.py` (also run by `python -m scripts.benchmark`) measures:
  - A: normal inference
  - B: verification
  - C: first secure deployment, plus its components
  - D: inference after verified deployment
- It reports median, p95, mean, minimum, number of runs, the machine description and the model size.
- It also writes `manifest_sizes.csv` for every artifact type.
- A new figure is produced: `fig_inference_overhead.png`.

**Demo.** `scripts/demo.py` runs the 13-step demo in a throw-away workspace, so real keys and artifacts are never touched.

## 4. Updated tests

| | Count |
|---|---|
| Baseline tests (5 October) | 113 |
| New tests | 30 |
| **Total** | **143** |
| Passed / failed / skipped | **143 / 0 / 0** |
| Runtime (`pytest -q`, incl. the slow backdoor test) | 32 s |

New test files and what they cover:

| File | Tests | What they cover |
|---|---|---|
| `tests/integration/test_external_models.py` | 17 | Policy separation; E7-A to E7-F; impersonation; relabelling; import hardening; publisher trust |
| `tests/integration/test_revocation_experiment.py` | 5 | Gateway block after revocation; key blast radius; bypass attempts; the E5-C4 limitation pinned as a test |
| `tests/integration/test_scenarios.py` | +4 | Scenarios F and G run fully, plus specific assertions |
| `tests/integration/test_inference_benchmark.py` | 2 | Benchmark output complete; manifest sizes for all 5 artifact types |
| `tests/integration/test_demo.py` | 2 | Demo shows every promised outcome; refuses to delete a non-demo folder |

No existing test was removed or weakened. The only edited line in an existing test file widens the scenario list from A–D to A–D, F, G.

## 5. Updated experiments

Overall: **44 / 44** variants ended with the expected status (`results/attacks/summary.csv`).

| Experiment | Scenario | Variants | Result |
|---|---|---|---|
| 1 Dataset tampering | A | 5 | 5 / 5 as expected |
| 2 Model substitution | B | 4 | 4 / 4 |
| 3 Invalid signature | D | 7 | 7 / 7 |
| 4 Broken provenance | C | 5 | 5 / 5 |
| **5 Revocation** | **F (new)** | **9** | **9 / 9** (incl. one documented limitation) |
| 6 Poisoned before signing | E | 5 | 5 / 5 (E2 backdoor success 77.2 %, E4 51.2 %) |
| **7 Untrusted external source** | **G (new)** | **9** | **9 / 9** (incl. one documented limitation) |

Experiment 7 results:

| Variant | Situation | Result | Checks |
|---|---|---|---|
| E7-A | Trusted publisher | VERIFIED, labelled external | — |
| E7-A2 | Fine-tuned on it | VERIFIED and deployed | — |
| E7-B | Unknown publisher | FAILED | V3, V4 |
| E7-C | Modified after signing | FAILED | V1 |
| E7-D1 | Unsigned, no manifest | REFUSED at import | — |
| E7-D2 | Signature stripped | REFUSED at import | — |
| E7-E | Publisher key revoked | FAILED | V4 |
| E7-E2 | Model fine-tuned from it | FAILED and blocked | V6 |
| **E7-F (limitation)** | Trusted publisher's backdoored model | **VERIFIED**; clean accuracy 93.3 %, backdoor success rate 100 % | — |

Experiment 5 results:

| Variant | Action | Result | Checks |
|---|---|---|---|
| E5-0 | Control | VERIFIED and deployed | — |
| E5-A1 / A2 | Revoke the base model | Model FAILED, gateway **blocked** | V6, V7 |
| E5-B1 | Revoke the training key | FAILED | V4, V6 |
| E5-B2 | Dataset signed by another role | still VERIFIED | — |
| E5-C1 | Delete the index row | FAILED | V7 |
| E5-C2 | Delete the revoked key | FAILED | V3, V4, V6 |
| E5-C3 | Overwrite the cached status | FAILED | V6, V7 |
| **E5-C4 (limitation)** | Flip the `revoked` flag back in the trusted SQLite index | **VERIFIED**: the revocation is undone | — |

## 6. New benchmark results

All values from the reference environment (`results/metrics/inference_benchmark.json`), median with p95.

| | Measurement | Runs | Median (ms) | p95 (ms) |
|---|---|---|---|---|
| A | Normal inference, 1 sample | 1,000 | 0.080 | 0.136 |
| A | Normal inference, batch 360 | 300 | 6.98 | 8.60 |
| B | Full chain verification V0–V9 (model + 3 ancestors) | 200 | 7.95 | 11.56 |
| C1 | Verify + audit log + TOCTOU-safe read | 100 | 30.5 | 37.6 |
| C2 | Safe load (safetensors) | 100 | 0.93 | 1.41 |
| C3 | Smoke test (360 samples) | 100 | 7.76 | 10.36 |
| C | **First secure deployment (gateway, total)** | 30 | **235.3** | 274.6 |
| D | Inference after verified deployment, 1 sample | 1,000 | 0.080 | 0.144 |
| D | Inference after verified deployment, batch 360 | 300 | 6.98 | 8.53 |

The model is 153,944 bytes and has 38,282 parameters.

- **Finding 1:** inference after a verified deployment costs the same as normal inference (0.080 ms vs 0.080 ms median), because verification is not on the prediction path.
- **Finding 2:** the first secure deployment (235 ms) is about 30 times the pure verification time. It is dominated by SQLite audit-trail writes and by a **second chain verification** that happens when the deployment record is registered. This cost is paid once per deployment. Removing the duplicate verification is a possible optimisation.

**Manifest sizes** (`results/metrics/manifest_sizes.csv`):

| Artifact | Signed envelope on disk | Canonical signed payload | Merkle sidecar | Artifact size |
|---|---|---|---|---|
| dataset (train) | 3,036 B | 1,756 B | 68,068 B | 147,571 B |
| dataset (fine-tune) | 3,052 B | 1,772 B | 29,784 B | 64,649 B |
| base model (internal) | 2,068 B | 1,239 B | — | 153,944 B |
| external base model | 1,412 B | 826 B | — | 153,944 B |
| fine-tuned model | 2,370 B | 1,487 B | — | 153,944 B |
| deployment record | 1,643 B | 1,008 B | — | 1,388 B |

Signed envelopes are 1.4–3.1 KB. The dataset Merkle sidecar is the largest piece of metadata: it is linear in the number of rows, at about 46 % of the CSV size here.

Re-measured crypto benchmark (`results/metrics/benchmark.csv`, 5 repeats):

- SHA-256 runs at about 1.1–1.2 GB/s from 1 MiB upwards; 256 MiB takes 220 ms.
- Ed25519 signing takes 0.03–0.06 ms and verification 0.11–0.20 ms, independent of artifact size.
- The pipeline's attestation took 10.8 ms against 1,261 ms of training (0.86 %, small CPU model, workload-dependent).

## 7. Docker status

**IMPLEMENTED / STATICALLY REVIEWED / LOCAL EXECUTION REQUIRED.**

Docker could not be executed in the reference environment: there is no Docker daemon, and outbound access to Docker Hub and to the PyTorch wheel index is blocked. The compose file was validated with `docker compose config`, which parses it without starting anything.

Fixes applied:

- `.dockerignore` now excludes `.venv/`, `venv/`, `demo-ws/`, `*.pem`, tests and docs. Before, a virtualenv created in the repo root as the README instructs, PyTorch included, would have been sent as build context.
- The API health check has a start period.
- Optional profiles were added: `experiments` (attacks A–G) and `demo`.
- The Makefile is copied into the image.

To run locally:

```bash
docker compose -f docker/docker-compose.yml up --build
```

Expected output:

1. The image builds (a few minutes the first time; CPU PyTorch is downloaded).
2. `pipeline` prints `[stage 1]` … `[stage 4] gateway: VERIFIED -> DEPLOYED` and exits with code 0.
3. `api` starts and becomes healthy (`Uvicorn running on http://0.0.0.0:8000`).
4. `dashboard` starts (`You can now view your Streamlit app`).
5. Open http://localhost:8000/docs and http://localhost:8501.

## 8. CI/CD status

**IMPLEMENTED, NOT YET EXECUTED.** There is no GitHub repository yet, so neither workflow has run on GitHub.

What was checked:

- Both workflow files pass `actionlint`.
- The `run:` steps of `attest-and-verify` were extracted from the YAML and executed locally in the reference environment: key generation, pipeline, re-verification, negative tamper control (tampered model → FAILED), attacks without E (39/39), and the evidence key guard. All succeeded.
- The `ci.yml` key guard was tested against a git copy of the repository.

Fixes applied:

- **Real bug found:** the `ci.yml` "no private key committed" guard searched for the literal string `PRIVATE KEY-----`, which also appears in the workflow file itself, so it would have failed on every run. The pattern is now assembled at runtime. Tested: it passes on the clean repository and still catches a deliberately committed `.pem` key.
- The OIDC token permission (`id-token: write`) is now granted only to the optional Sigstore job, not to the job that holds signing keys.
- Evidence is uploaded even when a step fails.
- A new guard checks that no private key appears in the uploaded evidence.
- Timeouts and concurrency control were added.
- `ruff` is pinned to the validated version (0.17.1), so lint results cannot change when ruff adds rules.
- Step names now cover scenarios F and G.

## 9. Remaining limitations

1. **Signed content is not safe content:**
   - poison signed before attestation verifies (E2, E4);
   - a trusted publisher's backdoored model verifies (E7-F).
   Content checks are heuristic and give WARNING only.
2. **Revocation state lives in the trusted SQLite index.** Editing its `revoked` flag undoes a revocation (E5-C4), and anyone who can write the database can add a trusted key. Fix: a signed, pinned trust root plus an append-only revocation list or transparency log.
3. **Revocation is local:** a copy verified elsewhere with an old trust store would still pass.
4. **Prototype key handling:** private keys are 0600 files or CI secrets (production: KMS/HSM or keyless Sigstore). The API has no authentication or TLS.
5. **Publisher trust is a manual, out-of-band decision.** There is no Sigstore or OpenSSF model-signing interoperability yet, and no import endpoint in the API or dashboard yet (CLI and library only).
6. **Not yet run outside the reference environment:**
   - all numbers are from that environment, not team hardware;
   - Docker and CI have not been executed;
   - tests ran on Python 3.13 only, while CI uses 3.11.
7. **The gateway verifies the chain twice** during a first deployment (once to load the model, once to register the deployment record). This is correct, but slower than necessary.

## 10. Next steps

1. Create the GitHub repository and push v0.3, then record the first CI runs (`ci`, `attest-and-verify`). Owner: MEKALA Rambabu.
2. Run `docker compose -f docker/docker-compose.yml up --build` on a team machine and record the result. Owner: MEKALA Rambabu.
3. Re-run the full validation on team hardware with `--machine-label` and add a journal entry. Owner: DAMA Dola Krishna.
4. Code walkthroughs: each member presents and runs the modules they own (section 11).
5. Experiment 7 follow-up: decide on Sigstore / OpenSSF model-signing interoperability (analyse or implement); add an import endpoint and a dashboard view. Owner: Karan DESHMUKH.
6. Inference: repeat the benchmark on team hardware; optionally remove the duplicate verification in the gateway. Owner: JOGI Sudheer reddy.
7. State of the art: verify every reference. Owners: all four.

## 11. Team ownership

Ownership (who is responsible for an area), not a record of individual contributions.

| Member | Role | Owns in v0.3 |
|---|---|---|
| Karan DESHMUKH | Technical Lead / Security Architecture | Architecture and integration, provenance and verifier design, external-model design (Experiment 7), deployment gateway, API, coordination, professor demo |
| JOGI Sudheer reddy | AI / ML Engineer | Dataset and training pipeline, backdoor experiments (E, E7-F), inference-overhead benchmark |
| DAMA Dola Krishna | Testing / Documentation / Quality Engineer | Test suite, experimentation journal, results collection, re-measurement on team hardware, dashboard support, weekly reports |
| MEKALA Rambabu | Security / DevOps Engineer | Hashing, signatures, key and publisher-key handling, revocation (Experiment 5), Docker, CI/CD |

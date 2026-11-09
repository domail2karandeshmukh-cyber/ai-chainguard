# AI-ChainGuard — Progress Update v0.4 (9 November 2026)

*ESAIP Master 1, Projet Applicatif 2 · Referent: Sofiane HAMRIOUI · Team: Karan DESHMUKH, JOGI Sudheer reddy, DAMA Dola Krishna, MEKALA Rambabu*

**Evidence rule (unchanged).** A feature is reported as completed only when code and repeatable execution evidence exist. Every number below comes from one run on **9 November 2026 in the AI-assisted reference development environment** (cloud Linux container, Intel Xeon @ 2.10 GHz, 2 logical CPUs, 8 GB RAM, Python 3.13.16, PyTorch 2.15.0 CPU execution). Raw logs: `results/validation_logs/`; the v0.3 results are archived unchanged in `results/archive_2026-10-16_v0.3/`. Docker was executed on team hardware (Karan's MacBook Air) on 16 October 2026; tests and benchmarks have not yet been re-run on team hardware.

## 1. What v0.4 changes

| # | Item | Status |
|---|---|---|
| 1 | **Signed, pinned, append-only trust log** (`chainguard/trustlog.py`): keys and revocations are records signed by the `release_manager` root key, hash-chained, pinned in `keys/trust_root.json`; the verifier replays it (V3/V4/V7) and fails closed when it is missing, truncated or tampered with | Completed, tested |
| 2 | **Limitation E5-C4 closed**: editing the SQLite index no longer un-revokes; reported as `INDEX_TAMPERING`. Four new Scenario F variants attack the log itself (E5-C5 rogue key, C6 truncate, C7 edit, C8 delete): all FAIL | Completed |
| 3 | **Interoperability**: any attestation exports as an in-toto Statement v1 inside a DSSE envelope, with a ChainGuard or **SLSA Provenance v1** predicate (`chainguard/interop.py`; CLI `export`; API `GET /artifacts/{id}/attestation`) | Completed, tested |
| 4 | **Experiment 7 in the API and dashboard**: `POST /external/publishers`, `POST /external/import`, `GET /external`; dashboard page **External Models** with four one-click publisher simulations | Completed |
| 5 | Dashboard pages **Trust Log** (records + live sandboxed bypass attempts) and **Why ChainGuard** (comparison) | Completed |
| 6 | Dashboard **standalone mode** (`CHAINGUARD_STANDALONE=1`): the API is embedded in-process for one-container deployments | Completed |
| 7 | Deployment record binds the trust-log head (`trust_log.seq`, `trust_log.head`) | Completed |
| 8 | `scripts/run_validation.sh` (whole validation sequence with machine label) and `scripts/trustlog_benchmark.py` | Completed |
| 9 | IEEE conference paper *Signed Is Not Safe* (`paper/`), figures regenerated from `results/` | Completed |
| 10 | Docs: README, 03 comparative table, 04 threat model, 07 technical description, 08 attack scenarios | Completed |

Development note: like v0.2 and v0.3, the v0.4 changes were produced with AI-assisted code generation and validated by execution in the reference environment. Team walkthrough and reproduction on team hardware remain planned.

## 2. Tests

| | v0.2 (5 Oct) | v0.3 (16 Oct) | **v0.4 (9 Nov)** |
|---|---|---|---|
| Tests passed / failed / skipped | 113 / 0 / 0 | 143 / 0 / 0 | **166 / 0 / 0** |
| Runtime (`pytest -q`) | — | 32 s | 37 s |
| Attack/control variants as expected | 26 / 26 | 44 / 44 | **48 / 48** |

New in v0.4: `tests/unit/test_trustlog.py` (10: genesis and pin, chaining, truncation, appended forgery, edited record, substituted log, root rotation, missing file), `tests/integration/test_revocation_experiment.py` (+6 replacing the pinned limitation: index un-revoke detected, rogue key, truncate, edit, delete, report carries the pinned head), `tests/integration/test_interop.py` (6: DSSE PAE vector from the specification, round trip and tampering, in-toto and SLSA exports, Merkle by-product), `tests/integration/test_api.py` (+2: attestation and trust-log endpoints, external publisher and import endpoints). `test_scenarios.py` now asserts 13 Scenario F variants.

## 3. Experiments

| Experiment | Scenario | Variants | Result |
|---|---|---|---|
| 1 Dataset tampering | A | 5 | 5 / 5 |
| 2 Model substitution | B | 4 | 4 / 4 |
| 3 Invalid signature | D | 7 | 7 / 7 |
| 4 Broken provenance | C | 5 | 5 / 5 |
| **5 Revocation** | **F** | **13** (9 in v0.3) | **13 / 13**; E5-C4 now FAILED; C5–C8 FAILED |
| 6 Poisoned before signing | E | 5 | 5 / 5 (E2 backdoor success 77.2 %, E4 51.2 %) |
| 7 Untrusted external source | G | 9 | 9 / 9 (E7-F limitation unchanged: 100 % backdoor success) |

Scenario F detail: see `docs/08_attack_scenarios.md`. What remains trusted is what the threat model always said: the keys directory (root private key and pin), the policy and the verifier.

## 4. Benchmarks (reference environment, median / p95 in ms)

| | Measurement | v0.3 | **v0.4** |
|---|---|---|---|
| A | Normal inference, 1 sample | 0.080 / 0.136 | 0.093 / 0.193 |
| B | Full chain verification V0–V9 (model + 3 ancestors) | 7.95 / 11.56 | **8.17 / 12.87** (trust-log replay included) |
| C | First secure deployment (gateway, total) | 235.3 / 274.6 | 249.2 / 277.1 |
| D | Inference after verified deployment, 1 sample | 0.080 / 0.144 | 0.092 / 0.189 |

The trust log adds about 0.2 ms to a verification with a 5-record log. `scripts/trustlog_benchmark.py`: replaying 5 / 50 / 500 / 2 000 records costs 1.2 / 7.3 / 73 / 282 ms when every signature is verified (≈ 0.15 ms per record, Ed25519-bound) and 0.25 / 0.8 / 7.6 / 31 ms with the per-process signature cache. Large organisations would checkpoint the log (a signed snapshot of the state) rather than replay it from genesis.

Pipeline: clean accuracy 95.0 %; attestation 12.1 ms vs 1 320 ms training (0.92 %). Manifest sizes unchanged (1.4–3.1 KB envelopes; the two new fields add about 30 bytes to internal envelopes).

## 5. Remaining limitations

1. **Signed content is not safe content** (E2, E4, E7-F): unchanged, and the subject of the paper.
2. **The trust log is local and single-writer.** A verifier with a stale copy would not see a recent revocation. Next step: publish records to a shared transparency log (Rekor-style) or distribute signed snapshots.
3. **Prototype key handling**: long-lived Ed25519 keys in files or CI secrets; no API authentication or TLS.
4. **Not yet run outside the reference environment** (tests, benchmarks); CI not executed on GitHub (no repository yet).
5. **Gateway verifies the chain twice** on first deployment (unchanged, documented).

## 6. Next steps

1. GitHub repository + first CI runs — MEKALA Rambabu.
2. `scripts/run_validation.sh` on team hardware, journal entry — DAMA Dola Krishna.
3. Module walkthroughs — all four.
4. Transparency-log publication of trust-log records; Sigstore keyless evaluation — Karan DESHMUKH, MEKALA Rambabu.
5. Benchmark on team hardware; optional removal of the duplicate gateway verification — JOGI Sudheer reddy.

## 7. Team ownership (v0.4)

| Member | Role | Owns |
|---|---|---|
| Karan DESHMUKH | Technical Lead / Security Architecture | Architecture and integration, verifier and trust-log design, external-model design, deployment gateway, API, interoperability export, coordination, paper |
| JOGI Sudheer reddy | AI / ML Engineer | Dataset and training pipeline, backdoor experiments (E, E7-F), inference-overhead benchmark |
| DAMA Dola Krishna | Testing / Documentation / Quality Engineer | Test suite, experimentation journal, results collection, validation script and re-measurement on team hardware, dashboard support, reports |
| MEKALA Rambabu | Security / DevOps Engineer | Hashing, signatures, key and publisher-key handling, revocation and trust log operations, Docker, CI/CD |

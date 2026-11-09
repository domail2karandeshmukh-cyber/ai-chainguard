# Experimentation journal

*One entry per experiment or significant decision. Never delete entries; add corrections as new entries. Link the result files.*

## Entry template

```
### YYYY-MM-DD · <short title> · <author>
Goal:
Setup (commit, command, parameters, seed, machine):
Result (numbers, files in results/):
Interpretation:
Decision / next step:
```

---

### 2026-10-05 · Reference run of the full prototype · AI-assisted baseline validation (team validation planned)

**Goal:** first complete measurement of pipeline, attacks and costs.
**Setup:** `python -m ml_pipeline.run_pipeline` (seed 42, 15 + 8 epochs), `python -m attacks.run_all`, `python -m scripts.benchmark` (5 repeats), reference development environment (cloud Linux container, 2 vCPU, CPU only, Python 3.13, PyTorch 2.x). Not yet reproduced on team hardware.
**Result:**
- Pipeline: 4 stages attested; gateway VERIFIED → deployed; clean test accuracy 95.0 %; release root recorded in `results/pipeline/last_run.json`.
- Overhead: 13 ms of attestation crypto vs 1,383 ms training (0.94 %); gateway verification 8.6 ms.
- Attacks: 26/26 variants as expected (`results/attacks/summary.csv`).
- Benchmark: SHA-256 ≈ 1.05 GB/s; Ed25519 sign 0.05 ms, verify 0.13–0.22 ms; registration ≈ 11 ms fixed (SQLite bookkeeping).
**Interpretation:** cryptographic cost is negligible for this model size; hashing dominates for large artifacts (linear).
**Next:** repeat on a team laptop for comparison; add a 1 GB model file to the benchmark.

### 2026-10-05 · Corner-trigger heuristic false positives · AI-assisted baseline validation (team validation planned; area owner: JOGI Sudheer reddy)

**Goal:** zero false positives on clean data.
**Observation:** first version flagged a sample when the *mean* of a 2×2 corner ≥ 12; on the 1,797 clean digits this flagged 11 samples (top-right and bottom-right corners, mostly 1s and 7s).
**Change:** require the *minimum* of the four pixels ≥ 12. Clean data: 0 flags. Poisoned data (8 %): 80 flags, 100 % labelled 7.
**Interpretation:** a heuristic tuned on the defender's knowledge of the trigger; E4 shows the cost of that assumption.

### 2026-10-16 · v0.3 full run: Experiments 5 and 7, inference benchmark, manifest sizes · AI-assisted baseline validation (team validation planned)

**Goal:** validate the v0.3 additions and re-run the complete evidence set.
**Setup:** reference development environment (cloud Linux container, Intel Xeon @ 2.10 GHz, 2 logical CPUs, 7.8 GB RAM, Python 3.13.16, PyTorch 2.14.1 CPU execution, 1 torch thread). Commands in order: `ruff check .`, `pytest -q`, `python -m ml_pipeline.run_pipeline`, `python -m attacks.run_all`, `python -m scripts.benchmark`, `python -m scripts.make_figures`. Logs: `results/validation_logs/`. **Not yet reproduced on team hardware.**
**Result:**
- Tests: 143 passed, 0 failed, 0 skipped, 32 s (baseline: 113).
- Pipeline: 4 stages attested, gateway VERIFIED → deployed; clean accuracy 95.0 %; attestation 10.8 ms vs 1,261 ms training (0.86 %); gateway verification 8.9 ms.
- Attacks: 44/44 variants as expected (A–E unchanged at 26/26; new F 9/9, G 9/9).
- Experiment 7 limitation (E7-F): trusted publisher's backdoored model VERIFIED, clean accuracy 93.3 %, ASR 100 %.
- Experiment 5 limitation (E5-C4): editing the revoked flag in the trusted SQLite index undoes a revocation.
- Inference (medians): normal single prediction 0.080 ms, after verified deployment 0.080 ms (n = 1,000 each); full chain verification 7.9 ms (n = 200); first secure deployment through the gateway 235 ms (n = 30).
- Manifest sizes: 1.4–3.1 KB per signed envelope; dataset Merkle sidecars 30–68 KB.
**Interpretation:** verification belongs at load/deployment time; it adds nothing to each prediction. The gateway's first deployment is dominated by SQLite audit writes and a second chain verification during deployment-record registration, not by cryptography.
**Next:** repeat on a team laptop with `--machine-label`; consider removing the duplicate verification in the gateway; signed revocation list for E5-C4.

### 2026-11-09 · v0.4 full run: signed trust log, Experiment 5 bypasses C4–C8, interoperability export · AI-assisted baseline validation (team validation planned)

**Goal:** close the E5-C4 limitation with the signed trust log, add the five new bypass variants and the in-toto/DSSE/SLSA export, and re-run the complete evidence set for the final presentation and the IEEE paper.
**Setup:** reference development environment (cloud Linux container, Intel Xeon @ 2.10 GHz, 2 logical CPUs, 8.2 GB RAM, Python 3.13.16, PyTorch 2.15.0 executed on CPU only, no GPU). `scripts/run_validation.sh` in order: `ruff check .`, `pytest -q`, `keys init`, `python -m ml_pipeline.run_pipeline`, `python -m attacks.run_all`, `python -m scripts.benchmark`, `python -m scripts.make_figures`, `python -m scripts.trustlog_benchmark`, `keys trust-log --json`. Logs and `environment.txt`: `results/validation_logs/`. **Not yet reproduced on team hardware; GitHub Actions configured but not yet executed.**
**Result:**
- Tests: 168 passed, 0 failed, 0 skipped, 36 s (v0.3: 143). `ruff` clean.
- Pipeline: 4 stages attested, gateway VERIFIED → deployed; clean accuracy 95.0 %; attestation 10.7 ms vs 1,288 ms training (0.83 %); gateway verification 8.5 ms.
- Attacks: 48/48 variants with the predicted outcome (A 5, B 4, C 5, D 7, E 5, F 13, G 9). Detection time 1.7–15.1 ms, median 7.5 ms.
- Experiment 5: E5-C4 (revoked flag cleared in SQLite) now FAILED with an `INDEX_TAMPERING` event; new C5 rogue key, C6 truncated log, C7 edited record, C8 deleted log all FAILED (fail closed); the index-only bypasses C1–C3 still FAILED.
- Experiment 6/7 boundary unchanged: E2 VERIFIED + deployed, 94.2 % clean accuracy, 77.2 % ASR; E3 WARNING, blocked; E4 VERIFIED, 51.2 % ASR; E7-F VERIFIED import, 93.3 %, 100 % ASR.
- Inference (medians): 0.084 ms before and 0.085 ms after the verified deployment (n = 1,000 each); full chain verification 8.5 ms, p95 12.2 ms (n = 200); first secure deployment 253 ms (n = 30; C1 31 ms, C2 1.1 ms, C3 8.3 ms).
- Trust-log replay (cold, every signature verified): 0.8 / 6.9 / 69 / 288 ms for 5 / 50 / 500 / 2,000 records (≈0.14 ms per record); warm 0.16 / 0.8 / 7.7 / 31 ms (≈15 µs per record).
- Manifest sizes unchanged: 1.4–3.1 KB per signed envelope; Merkle sidecars 30–68 KB; SHA-256 ≈1.2 GB/s (256 MiB in 220 ms); Ed25519 sign 0.04 ms, verify 0.12–0.14 ms.
**Interpretation:** the trust decisions are now protected by the same mechanism as the artifacts; what remains trusted is the keys directory (root key and pin). The semantic boundary is unchanged, as expected: signatures do not see content.
**Next:** run `scripts/run_validation.sh` on a team laptop and append the entry; push the repository and let CI run; checkpoint signed trust-log snapshots.

### 2026-11-09 (evening) · Repository published on GitHub; first GitHub Actions runs · AI-assisted, validated by execution

**Goal:** publish the repository and run the two CI workflows on GitHub for the first time.
**Setup:** https://github.com/domail2karandeshmukh-cyber/ai-chainguard (public), branch `main`, commit 679f855. GitHub-hosted runner `ubuntu-latest`, Python 3.11.18 (the minimum supported version), PyTorch 2.15.0+cpu, cryptography 50.0.2, ruff 0.17.1 (pinned).
**Result:**
- `ci` (run 42666510422): `ruff` clean; private-key guard passed; fast tests 167 passed (1 deselected), slow backdoor test 1 passed: 168/168.
- `attest-and-verify` (run 42666509774): ephemeral keys initialised; four-stage attested pipeline, gateway VERIFIED → DEPLOYED; independent re-verification of the deployed model VERIFIED; negative control (one flipped byte of the deployed model) FAILED as required; attack scenarios A–D, F, G 43/43 as expected (the runner exits non-zero otherwise); evidence uploaded as a workflow artifact. The optional Sigstore job was skipped (disabled by default).
**Interpretation:** the test suite and the CI release gate also hold outside the reference environment, on Python 3.11. Benchmarks were not measured in CI: shared runners are not a stable timing environment.
**Next:** run `scripts/run_validation.sh` on a team laptop; enable the Sigstore job if keyless signing is wanted.

### [date] · [next experiment] · [author]

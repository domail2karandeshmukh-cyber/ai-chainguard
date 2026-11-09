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

### [date] · [next experiment] · [author]

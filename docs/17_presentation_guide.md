# Final presentation guide (v0.4, 9 November 2026)

*For the team. Everything below is backed by a file in the repository; the path is given each time so any number can be shown live.*

## 1. The one-minute version

> AI models are assembled from datasets, downloaded pretrained models and fine-tuning runs owned by different parties. Software supply-chain tools (Sigstore, SLSA, in-toto, OpenSSF Model Signing) sign one file or one build; nothing links those stages, decides who may sign which one, revokes along the links or gates deployment. AI-ChainGuard does that: every artifact gets a signed manifest that embeds its parents' digests, a verifier runs ten checks recursively, trust and revocation live in a signed, append-only log, and a gateway verifies once before loading the model. We then **measured** where this stops: every one of 48 post-signing manipulations is caught in under 15 ms, but a dataset poisoned *before* signing deploys as VERIFIED with a 77 % backdoor success rate, and a trusted publisher's backdoor with 100 %. **Signed is not safe** — and a supply-chain control has to say so.

## 2. Numbers to have in your head (all from the 9 Nov 2026 run)

| Claim | Number | Where it comes from |
|---|---|---|
| Tests | **168 passed**, 0 failed, 0 skipped, ~37 s | `results/validation_logs/2_pytest.log` |
| Attack suite | **48 / 48** variants with the predicted outcome, 7 experiments (A–G) | `results/attacks/summary.csv`, `results/figures/attack_table.md` |
| Detection | 1.7–15.1 ms per verification incl. the chain (median 7.5 ms) | `paper/figures/analysis.json` |
| Trust-log attacks | E5-C4 (edit SQLite) now FAILS; C5 rogue key, C6 truncate, C7 edit, C8 delete all FAIL | `results/attacks/scenario_F.json` |
| Signed poison | E2: VERIFIED + deployed, clean acc 94.2 %, backdoor 77.2 %; E3 content checks: WARNING + blocked; E4 adaptive trigger: VERIFIED, 51.2 % | `results/attacks/scenario_E.json` |
| Trusted publisher backdoor | E7-F: VERIFIED, clean acc 93.3 %, backdoor 100 % | `results/attacks/scenario_G.json` |
| Pipeline | 4 stages VERIFIED → DEPLOYED, clean accuracy 0.950; attestation 10.7 ms vs 1 288 ms training (0.83 %) | `results/pipeline/last_run.json` |
| Verification cost | full chain 8.5 ms median (p95 12.2); first secure deployment 253 ms once | `results/metrics/inference_benchmark.csv` |
| Inference cost | 0.084 ms before vs 0.085 ms after verified deployment: **zero per prediction** | same |
| Trust log cost | 0.14 ms per record cold, 15 µs cached; 5 / 50 / 500 / 2 000 records = 0.8 / 6.9 / 69 / 288 ms | `results/metrics/trustlog_benchmark.csv` |
| Manifest size | 1.4–3.1 KB per artifact; dataset Merkle sidecar 30–68 KB | `results/metrics/manifest_sizes.csv` |
| Crypto | SHA-256 ≈ 1.2 GB/s; Ed25519 sign 0.04 ms, verify 0.12–0.14 ms | `results/metrics/benchmark.csv` |
| Code | ≈ 8 200 lines of Python + 1 600 lines of tests | `wc -l` |
| Team hardware | Docker build + Compose + pipeline + API + dashboard on Karan's MacBook Air, 16 Oct 2026 (v0.3) | Progress Report 2 |

Say "reference environment" for every number except the Docker run: cloud Linux container, 2 vCPU Xeon @ 2.10 GHz, CPU only. Tests and benchmarks have **not** been re-run on team laptops yet (`scripts/run_validation.sh` does it in one command — if someone runs it before the presentation, swap in those numbers).

## 3. Live demo click-path (dashboard, ~4 minutes)

Start once: `make standalone` (or `make api` + `make dashboard`). If the workspace is empty, click **Build the attested chain now** on the Overview page.

1. **Overview** — 5 artifacts, all VERIFIED, "Signed trust log: 4 records".
2. **Attack Lab** — Target `digits-train`, mode `flip_byte`, **Tamper** → FAILED, V1 + V2 names the changed line. **Restore original**.
3. **Trust Log** — show the records, then press **Un-revoke in SQLite** → FAILED with `INDEX_TAMPERING`; press **Truncate the log** → FAILED, "rollback". (Sandbox copies: the real workspace is untouched.)
4. **External Models** — **Trusted publisher** → VERIFIED, labelled EXTERNAL; **Unknown publisher** → FAILED (V3, V4), quarantined; **Unsigned model** → REFUSED.
5. **Why ChainGuard** — the comparison table; end on "no column reaches yes for poisoned content".

Terminal alternative: `python -m scripts.demo` (15 steps, pauses on Enter, every number measured live; runbook in `docs/15_professor_demo_10min.md`). Rehearsal without pauses: `python -m scripts.demo --auto` (≈10 s of computation; the workspace is re-verified at the end so Overview shows green afterwards).

**Fallbacks, in order:** (1) the dashboard in standalone mode needs no API process and no network (`make standalone`); (2) the terminal demo above; (3) the nine screenshots of the 9 Nov 2026 run in `docs/demo-screenshots/01_overview.png … 09_why_chainguard.png`, which cover every page of the click-path. Never pretend a failed step worked — say so and switch to the next fallback.

## 4. Slide-by-slide message (the 14-slide deck follows this order)

1. Title. 2. Incidents (torchtriton 2022, Hugging Face pickle models 2024/2025, 250-document poisoning 2025, EU AI Act Art. 15). 3. The gap: tools sign a file or a build, not the AI lineage; and "signed" is read as "safe". 4. What AI-ChainGuard does: four stages, parent digests inside signed payloads, roles, gateway. 5. The ten checks. 6. v0.4: the signed trust log (why the database was the weak point, what the log is, what fails now). 7. Live demo (slide 6 of the deck is the cue to switch to the app). 8. Experiments 1–5: 48 variants, all detected, with the detection-time figure. 9. Experiments 6–7: the boundary figure (77 % / 51 % / 100 % behind VERIFIED). 10. Cost: 0.83 % of training, 8.5 ms per verification, 0 per inference, 1.4–3.1 KB. 11. Interoperability: in-toto / DSSE / SLSA export; comparison table. 12. Engineering: 168 tests, 48 scenarios, Docker on team hardware (16 Oct), CI configured not run, dashboard, paper. 13. Limitations and next steps (honest), with the paper title "Signed Is Not Safe". 14. Team and ownership, questions. Slide-sized versions of the paper's figures are generated by `python paper/figures/make_slide_figures.py` (`paper/figures/slide_*.png`).

## 5. Questions the jury may ask

| Question | Answer |
|---|---|
| **Isn't this just Sigstore / cosign?** | Sigstore signs one artifact and gives keyless identities and a public log; we would happily sign *with* it. What it does not do is link dataset → model → fine-tune → deployment with a policy on roles, revoke along those links, or gate deployment. We export to its formats (in-toto / DSSE) rather than compete. |
| **Why not in-toto layouts or SLSA directly?** | They model a *software build*; the training step maps to it only partly (no reproducible build, weights are not reviewable). We borrow the Statement/DSSE format and the "builder identity" idea and add what AI needs: dataset row-level Merkle roots, two kinds of base model, external publishers, and a measured semantic boundary. |
| **What does VERIFIED actually prove?** | Exactly what trusted, unrevoked signers in authorised roles attested, through an intact ancestry — nothing about behaviour. We never upgrade it to "safe"; content checks only ever produce WARNING. |
| **What if a key is stolen?** | Its signatures are valid until it is revoked; revocation is a signed record that fails everything that key signed and everything downstream (E5-B1), and the blast radius is limited to that key (E5-B2). Production: HSM/KMS or short-lived Sigstore certificates. |
| **Can an insider undo a revocation?** | Not by writing the database any more (v0.4): the verifier replays the signed, pinned log; any disagreement is `INDEX_TAMPERING`. Truncating, editing or deleting the log fails closed. Whoever holds the root key and can rewrite the pin file controls trust — that is the stated trusted base. |
| **Why a hash chain and not a Merkle tree / blockchain?** | One writer, a few hundred records: a hash chain with a pinned head gives the same tamper-evidence at negligible cost. A Merkle tree matters for inclusion proofs in a *shared* log (Rekor/CT), which is the next step; blockchain adds cost without adding guarantees here. |
| **Why Ed25519?** | Deterministic signatures (no nonce reuse failure), 64-byte signatures, 32-byte keys, fast verification (0.12–0.16 ms), used by Sigstore and SSH. Not post-quantum; the signing primitive is one function and could be swapped. |
| **Why is the first deployment 253 ms?** | Audit-trail writes to SQLite and a second chain verification when the deployment record is registered; paid once per deployment. Removing the duplicate verification is a documented optimisation. Inference afterwards costs nothing extra. |
| **Does this scale to real models?** | Hashing is the only size-dependent cost: ≈ 1.2 GB/s, so a 1 GB model costs about a second once; signatures and verification do not depend on size; manifests stay 1.4–3.1 KB. The experiments use a small CNN on purpose so that 48 variants run in minutes. |
| **How do you detect backdoors then?** | We do not claim to. Content checks (label distribution, duplicates, a known trigger) are heuristics that only warn; an adaptive trigger evades them (E4). Stronger defences (Neural Cleanse, STRIP, spectral signatures) raise the bar; none closes it. The point of the project is to keep that evidence *separate* from the cryptographic evidence. |
| **Are the numbers from your laptops?** | The Docker run is (MacBook Air, 16 Oct). Tests and benchmarks come from the reference environment; `scripts/run_validation.sh "<machine>"` reproduces the whole run with one command and records the machine. |
| **How was the code produced?** | With AI-assisted code generation, validated by execution (168 tests, 48 scenarios, benchmarks regenerated by scripts). Ownership by module is in the README; walkthroughs per owner are the next team step. |
| **What is the research contribution?** | Measuring the boundary. Nobody argues a signature proves safety, but we quantify how much behaviour can hide behind a VERIFIED status (77 %, 51 %, 100 %), what post-signing attacks look like against a linked chain (48 variants), and what it all costs. The paper is `paper/signed_is_not_safe.pdf`. |

## 6. What not to claim

- Not "GitHub Actions passes" (the workflows exist and were checked statically; no repository run yet).
- Not "deployed in the cloud" (Docker Compose on a laptop is the demonstration path).
- Not "tests re-run on team hardware" (not yet).
- Not "detects poisoning" — it detects *tampering after signing* and *measures* that it cannot detect poisoning before signing.

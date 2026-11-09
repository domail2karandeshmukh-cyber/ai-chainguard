# 10-minute professor demo: runbook

*v0.4. Presenter: Karan DESHMUKH. One command, 15 steps, every number measured live.*

## Before the meeting (5 minutes, once)

```bash
cd ai-chainguard
source .venv/bin/activate              # Windows: .venv\Scripts\activate
python -m scripts.demo --auto          # rehearsal: must end with the SUMMARY block (~10-20 s)
```

If the rehearsal fails, use the fallback at the bottom. Keep a terminal at least 110 characters wide.

## During the meeting

```bash
python -m scripts.demo                 # or: make demo
```

The script pauses after every step. Read the cyan **SAY:** line, point at the coloured result, press **Enter**.
It creates a throw-away workspace `demo-ws/` (deleted and rebuilt each run), so your real keys and artifacts are never touched.

| # | Step | What the professor sees | Time |
|---|---|---|---|
| 1 | Clean supply chain | 2 datasets, base model, fine-tuned model, each with its signing role | 0:00 |
| 2 | Verify final model | the 10 checks V0-V9 listed one by one | 0:45 |
| 3 | VERIFIED | green badge, deployment record and release root | 1:30 |
| 4 | Provenance | tree: model → base model → dataset, with parent digests | 2:00 |
| 5 | Tamper with dataset | one label changed on line 5 of the signed training CSV | 2:45 |
| 6 | Verify again | dataset FAILED (V1, V2 names the changed line), model FAILED (V6) | 3:15 |
| 7 | FAILED | explanation: tampering upstream invalidates everything downstream | 3:45 |
| 8 | BLOCKED | gateway refuses to deploy; original restored → VERIFIED again | 4:00 |
| 9 | Invalid signature | one bit of the model's signature flipped → FAILED (V3) | 4:45 |
| 10 | Revocation | base model revoked → fine-tuned model FAILED (V7) and BLOCKED | 5:15 |
| 11 | Attack the trust itself (v0.4) | attacker clears the `revoked` flag in SQLite → still FAILED + `INDEX_TAMPERING` event (the v0.3 limitation E5-C4, closed); attacker truncates the signed trust log → FAILED, "rollback: log ends at #4, pin says #5" | 5:45 |
| 12 | Poisoned before signing | 8 % poison signed honestly → VERIFIED + DEPLOYED with a working backdoor; content checks ON → WARNING + BLOCKED | 6:30 |
| 13 | External models | trusted publisher → VERIFIED (labelled external); unknown publisher → FAILED (V3, V4); unsigned → REFUSED | 7:30 |
| 14 | Interoperability (v0.4) | the final model's attestation exported as an in-toto Statement with SLSA Provenance v1 in a DSSE envelope, verified independently | 8:15 |
| 15 | Metrics | attestation vs training time, verification ms, one prediction ms, manifest size | 8:45 |
| - | Summary | every outcome shown, one line each | 9:30 |

## Three sentences to say at the end

1. AI-ChainGuard proves **integrity and provenance**: every artifact is exactly what a trusted signer attested, through an intact chain, and the gateway refuses anything else.
2. It does **not** prove semantic safety: poison signed before attestation, or a backdoor shipped by a trusted publisher, verifies perfectly (steps 12 and 13).
3. Verification runs **once at deployment**, not before every prediction, so its cost does not grow with traffic.

## Likely questions

| Question | Short answer |
|---|---|
| Why not blockchain? | A transparency log gives tamper-evident history without a ledger; blockchain is an optional extension. |
| What if a signing key is stolen? | Its signatures are valid until the key is revoked; revocation then fails everything it signed (step 10, Experiment 5). Production: KMS/HSM or keyless Sigstore. |
| Can someone undo a revocation? | No longer (v0.4). Revocations are records of a signed, hash-chained, append-only log pinned in the keys directory. Editing the SQLite index is detected (`INDEX_TAMPERING`); truncating, editing or deleting the log fails closed (step 11, Scenario F variants C4–C8). What remains trusted is the keys directory itself. |
| Isn't this just Sigstore / in-toto / SLSA? | Those sign one artifact or one build. AI-ChainGuard links dataset → base model → fine-tuned model → deployment with a role policy and propagating revocation, and exports to their formats (step 14) rather than competing with them. See the dashboard page "Why ChainGuard". |
| What does the trust log cost? | About 0.14 ms per record on first replay (Ed25519-bound), 15 µs per record once signatures are cached; replaying the 5-record log costs 0.16 ms inside the 8.5 ms chain verification. Large organisations would checkpoint it. |
| Why Ed25519? | Deterministic, 64-byte signatures, fast, no nonce-reuse failure mode. |
| Can you detect backdoors? | Partially, with heuristic content checks that only raise WARNING; an adaptive trigger evades them (scenario E4). |
| Are these numbers from your laptops? | Not yet: the committed results come from the AI-assisted reference environment (cloud container). Team-hardware re-runs are the next step. The demo's own numbers are measured live on whatever machine runs it. |

## Fallback

- **Dashboard instead of terminal:** `make standalone` (one process, API embedded) or `uvicorn api.main:create_app --factory --port 8000` + `streamlit run dashboard/Overview.py`. Pages to show: Overview → Attack Lab (Tamper) → **Trust Log** (the six bypass buttons) → **External Models** (four publisher buttons) → **Why ChainGuard**.
- **Docker:** `docker compose -f docker/docker-compose.yml --profile demo run --rm demo` (needs one `docker compose ... up --build` first; executed on Karan's MacBook Air on 16 Oct 2026 with v0.3 — rebuild the image for v0.4).
- **Nothing runs:** show `results/figures/*.png` and `results/attacks/summary.csv`, which are committed results from the last full run.

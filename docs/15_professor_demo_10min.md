# 10-minute professor demo: runbook

*v0.3. Presenter: Karan DESHMUKH. One command, 13 steps, every number measured live.*

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
| 10 | Revocation | base model revoked → fine-tuned model FAILED (V7) and BLOCKED | 5:30 |
| 11 | Poisoned before signing | 8 % poison signed honestly → VERIFIED + DEPLOYED with a working backdoor; content checks ON → WARNING + BLOCKED | 6:15 |
| 12 | External models | trusted publisher → VERIFIED (labelled external); unknown publisher → FAILED (V3, V4); unsigned → REFUSED | 7:30 |
| 13 | Metrics | attestation vs training time, verification ms, one prediction ms, manifest size | 8:30 |
| - | Summary | every outcome shown, one line each | 9:15 |

## Three sentences to say at the end

1. AI-ChainGuard proves **integrity and provenance**: every artifact is exactly what a trusted signer attested, through an intact chain, and the gateway refuses anything else.
2. It does **not** prove semantic safety: poison signed before attestation, or a backdoor shipped by a trusted publisher, verifies perfectly (steps 11 and 12).
3. Verification runs **once at deployment**, not before every prediction, so its cost does not grow with traffic.

## Likely questions

| Question | Short answer |
|---|---|
| Why not blockchain? | A transparency log gives tamper-evident history without a ledger; blockchain is an optional extension. |
| What if a signing key is stolen? | Its signatures are valid until the key is revoked; revocation then fails everything it signed (step 10, Experiment 5). Production: KMS/HSM or keyless Sigstore. |
| Can someone undo a revocation? | Deleting index rows does not work (fails closed). Editing the revoked flag in the trusted SQLite index does: documented limitation E5-C4; fix = signed revocation list. |
| Why Ed25519? | Deterministic, 64-byte signatures, fast, no nonce-reuse failure mode. |
| Can you detect backdoors? | Partially, with heuristic content checks that only raise WARNING; an adaptive trigger evades them (scenario E4). |
| Are these numbers from your laptops? | Not yet: the committed results come from the AI-assisted reference environment (cloud container). Team-hardware re-runs are the next step. The demo's own numbers are measured live on whatever machine runs it. |

## Fallback

- **Dashboard instead of terminal:** `uvicorn api.main:create_app --factory --port 8000` and `streamlit run dashboard/Overview.py`; Attack Lab → run scenarios F and G.
- **Docker:** `docker compose -f docker/docker-compose.yml --profile demo run --rm demo` (needs one `docker compose ... up --build` first; not yet executed by the team).
- **Nothing runs:** show `results/figures/*.png` and `results/attacks/summary.csv`, which are committed results from the last full run.

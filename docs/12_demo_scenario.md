# Final demonstration scenario (15 minutes)

**Setup before the jury arrives** (fresh workspace, rehearsed twice):

```bash
export CHAINGUARD_HOME=$PWD/demo-ws && rm -rf demo-ws
python -m ml_pipeline.run_pipeline                      # ~10 s
uvicorn api.main:create_app --factory --port 8000 &
streamlit run dashboard/Overview.py &
python -m attacks.run_all                               # pre-computed results for the Attack Lab
```

| Time | Who | Step | What the jury should see |
| --- | --- | --- | --- |
| 0:00 | Karan DESHMUKH | Problem in one slide: lifecycle diagram, "integrity ≠ safety" | The research question |
| 1:30 | MEKALA Rambabu | Dashboard → Overview | 4 artifacts + deployment record, all VERIFIED |
| 2:30 | MEKALA Rambabu | Provenance Chain → focus the fine-tuned model; open the signed manifest | Parent digests inside the signed payload, release root |
| 4:00 | DAMA Dola Krishna | Attack Lab → target `digits-train`, mode `flip_label` → **Tamper** | FAILED; V1 + V2 with "1 line modified" |
| 5:00 | DAMA Dola Krishna | **Verify final model** | FAILED via V6: tampering upstream breaks everything downstream |
| 5:30 | DAMA Dola Krishna | **Restore original** | VERIFIED again |
| 6:00 | Karan DESHMUKH | Terminal: `python -m cli.main verify <final_id>` after editing one byte of the model | CLI report, exit code 1 |
| 7:00 | MEKALA Rambabu | Verify Artifact → Revoke the base model → verify the final model | FAILED via V7 (revoked ancestor) |
| 8:30 | JOGI Sudheer reddy | Attack Lab → Scenario E results | E2 VERIFIED + deployed with 77 % ASR: **the limitation** |
| 10:00 | JOGI Sudheer reddy | E3 vs E4 | Content checks catch the known trigger (WARNING, blocked) but not the adaptive one |
| 11:30 | DAMA Dola Krishna | Metrics page | 0.94 % overhead; hashing linear, signatures constant |
| 12:30 | MEKALA Rambabu | GitHub Actions run of `attest-and-verify` | CI gate + negative control |
| 13:30 | Karan DESHMUKH | Conclusion slide: guarantees, limits, future work | |
| 14:00 | all | Questions | |

**Fallbacks:** if the API is down, run the same steps with the CLI (`mvp-demo`, `verify`, `revoke`); screenshots of every page from the reference run are in `docs/demo-screenshots/`; retake them during rehearsal.

**Likely jury questions:** Why not blockchain? (transparency log gives tamper-evident history without a ledger) · What if the key is stolen? (residual risk; KMS, revocation, keyless Sigstore) · Why Ed25519? (deterministic, small, fast) · Can you detect backdoors? (partially; E4 shows evasion).

# Attack scenarios

Run: `python -m attacks.run_all` (all) or `--only A B` / `--skip-e`. Each scenario clones a freshly built clean chain into a temporary workspace, attacks it, verifies, and writes `results/attacks/scenario_<X>.json`. Result of the v0.4 reference run: **48/48 variants with the expected status** (26 in v0.2, 44 in v0.3).

## Scenario A — Dataset tampering

| Variant | Attack | Result | Checks |
| --- | --- | --- | --- |
| A0 | Control | VERIFIED | — |
| A1 | Flip labels on lines 10, 50, 100, 200, 400 | FAILED | V1, V2 (Merkle diff lists exactly those 5 lines) |
| A2 | Same, verify the fine-tuned model | FAILED | V6 (ancestor failed) |
| A3 | Append one injected row | FAILED | V1, V2 (1 line added) |
| A4 | One trailing space on one line | FAILED | V1, V2 |

## Scenario B — Model substitution

| Variant | Attack | Result | Checks |
| --- | --- | --- | --- |
| B0 | Control; gateway deploys | VERIFIED | — |
| B1 | Replace with attacker-trained model | FAILED, gateway blocks | V1 |
| B2 | One weight + 1e-6 (test accuracy unchanged) | FAILED, gateway blocks | V1 |
| B3 | Same weights re-saved as pickle | FAILED, gateway blocks | V1 |

B2 shows that integrity is stricter than behaviour: a functionally identical model is still rejected.

## Scenario C — Broken provenance

| Variant | Attack | Result | Checks |
| --- | --- | --- | --- |
| C0 | Control | VERIFIED | — |
| C1 | Delete parent dataset envelope + index row | FAILED | V5, V8 |
| C2 | Insider modifies the dataset and **re-signs it with the real data-steward key** | dataset alone VERIFIED; model FAILED | V5 |
| C3 | Edit the model's parent link without re-signing | FAILED | V3 |
| C4 | Validly signed model with no dataset parent (policy bypassed at registration) | FAILED | V8 |

C2 is the key result for hash-linking: a legitimate signature cannot rewrite history beneath existing descendants.

## Scenario D — Invalid signature

| Variant | Attack | Result | Checks |
| --- | --- | --- | --- |
| D0 | Control | VERIFIED | — |
| D1 | Flip one bit of the signature | FAILED | V3 |
| D2 | Replay a valid signature from another manifest | FAILED | V3 |
| D3 | Re-sign with an attacker key | FAILED | V3, V4 |
| D4 | Training key revoked | FAILED | V4, V6 |
| D5 | Data-steward key signs a model | FAILED | V4 |
| D6 | Signature not valid base64 | FAILED | V3 |

## Scenario E — Backdoor / data poisoning

BadNets-style: 2×2 saturated patch in the bottom-right corner, label forced to 7. ASR = share of non-7 test images classified as 7 once the trigger is added.

| Variant | Poison enters | Content checks | Status | Deployed | Clean acc | ASR |
| --- | --- | --- | --- | --- | --- | --- |
| E0 | never | on | VERIFIED | yes | 95.0 % | 0.0 % |
| E1 | **after** signing (8 %) | on | FAILED (V6) | no | — | — |
| E2 | **before** signing (8 %) | off | **VERIFIED** | **yes** | 94.2 % | **77.2 %** |
| E3 | before signing (8 %) | on | WARNING (V9) | no | 94.2 % | 77.2 % |
| E4 | before signing, left-bar trigger (5 %) | on | **VERIFIED** | **yes** | 94.4 % | **51.2 %** |

Interpretation for the report:

- **Strength:** once data is attested, any later poisoning is caught (E1).
- **Limitation:** attestation transfers trust to the signer; it does not create it. Poison present at signing time is faithfully preserved and verified (E2).
- **Semantic checks help but are not proof:** they flag the trigger family they model (E3: label drift + corner trigger) and miss an adaptive one (E4). They are reported as WARNING, never as cryptographic failure.
- Clean accuracy hardly changes (95.0 → 94.2 %), so ordinary testing would not reveal the backdoor.
- Fine-tuning on clean data weakens but does not remove the backdoor: base-model ASR 99.1 % (E2) and 99.4 % (E4) drop to 77.2 % and 51.2 % after fine-tuning. Fine-tuning is not a defence to rely on.

Figures: `results/figures/fig_attack_outcomes.png`, `results/figures/fig_backdoor_asr.png`.

### Supplementary run: poison in the fine-tuning dataset (10 November 2026)

The brief's example scenario injects the backdoor into the fine-tuning dataset, while E2 to E4 put it in the base model's training set. `python -m scripts.e2_finetune_poison` repeats E2 and E3 with the poison in the fine-tuning set instead: 8 % of its 437 rows (35 rows) get the same corner trigger and the label 7 before the data steward signs them; the base model is trained on clean data.

| Variant | Poison enters | Content checks | Status | Deployed | Clean acc | ASR |
| --- | --- | --- | --- | --- | --- | --- |
| FT-E2 | fine-tuning set, **before** signing (8 %) | off | **VERIFIED** | **yes** | 93.9 % | **25.3 %** |
| FT-E3 | fine-tuning set, before signing (8 %) | on | WARNING (V9: label distribution, corner trigger) | no | 93.9 % | 25.3 % |

The boundary is the same as in E2 and E3: signed poison verifies and deploys, and the content checks flag this trigger family so the gateway blocks it. The backdoor is weaker (25.3 % against 77.2 %) because eight epochs of fine-tuning on 35 poisoned rows teach it less than fifteen epochs of training with 8 % poison. The base model's attack success rate is 0 %, so the backdoor comes from the fine-tuning set alone. Result file: `results/attacks/e2_finetune_poison.json`. These two variants are not part of the paper's 48.

### Supplementary run: the same variants for ten other seeds (10 November 2026)

The reference run uses one seed (42). The seed decides the split of the digits, the rows that are poisoned, the initial weights and the order of the mini-batches. `python -m scripts.seed_robustness` repeats the four pipeline variants E0, E2, E3 and E4, unchanged, for the seeds 0 to 9 (40 runs), and runs seed 42 again as a check.

| Variant | Status in the 10 runs | Deployed | Clean accuracy (min to max, median) | ASR (min to max, median) |
| --- | --- | --- | --- | --- |
| E0 clean | 10 VERIFIED, no content flag | 10 | 95.8 to 98.6 %, 97.2 % | 0 % |
| E2 poison before signing | 10 VERIFIED | 10 | 95.8 to 98.3 %, 96.9 % | **74.4 to 94.8 %, 83.0 %** |
| E3 same poison, content checks | 10 WARNING | 0 (blocked) | same models as E2 | same models as E2 |
| E4 adaptive trigger | 10 VERIFIED | 10 | 96.4 to 98.1 %, 97.2 % | **58.3 to 90.1 %, 70.4 %** |

The status never changes, and the content checks raise no false alarm on the ten clean splits. Seed 42 reproduces the reference results exactly (95.0 % / 0 %; 94.2 % / 77.2 %; WARNING; 94.4 % / 51.2 %): the reference seed gives the second weakest backdoor of the eleven runs for E2 and the weakest for E4, so the figures quoted in the paper and the report are at the low end of what the attack achieves. Result file: `results/attacks/seed_robustness.json`. These runs are not part of the paper's 48.

---

## Scenario F — Revocation (Experiment 5, v0.3; extended in v0.4)

`python -m attacks.run_all --only F` · script `attacks/scenario_f_revocation.py` · every variant starts from a fresh clean chain.

**v0.4 change.** Trust and revocation now live in a signed, hash-chained, append-only log (`artifacts/trust/trust_log.jsonl`) whose records are signed by the `release_manager` root key and whose last record is pinned in `keys/trust_root.json` (`chainguard/trustlog.py`). The verifier replays the log at every verification; the SQLite index is only a convenience copy. E5-C4, reported as a limitation in v0.3, is therefore a detected attack, and four new variants attack the log itself.

| Variant | Action | Expected | Observed (v0.4 run) | Checks |
| --- | --- | --- | --- | --- |
| E5-0 | Control: nothing revoked, gateway deploys | VERIFIED | VERIFIED, deployed | — |
| E5-A1 | Revoke the base model, verify the fine-tuned model | FAILED | FAILED | V6, V7 |
| E5-A2 | Gateway asked to deploy that model | FAILED | FAILED, **blocked** | V6, V7 |
| E5-B1 | Revoke the `training_pipeline` key, verify the final model | FAILED | FAILED | V4, V6 |
| E5-B2 | Same revocation, verify a dataset signed by `data_steward` | VERIFIED | VERIFIED (blast radius limited to that key) | — |
| E5-C1 | Bypass: delete the revoked artifact's index row | FAILED | FAILED | V7 ("revocation state cannot be confirmed") |
| E5-C2 | Bypass: delete the revoked key from the index | FAILED | FAILED (the signed log still says revoked; missing row = index tampering) | V4, V6 |
| E5-C3 | Bypass: overwrite the cached `last_status` with VERIFIED | FAILED | FAILED (cached status never read) | V6, V7 |
| E5-C4 | Bypass: set the `revoked` flag back to 0 in SQLite (**v0.3 limitation**) | FAILED | FAILED, `INDEX_TAMPERING` event | V6, V7 |
| E5-C5 | Bypass: insert the attacker's key into `signers` as `training_pipeline`, substitute and re-sign the model | FAILED | FAILED ("never trusted in the signed trust log") | V3, V4 |
| E5-C6 | Bypass: truncate the trust log (drop the revocation record), clear the index flag | FAILED | FAILED (rollback: log ends before the pinned head) | V3, V4, V7 |
| E5-C7 | Bypass: edit the revocation record in place | FAILED | FAILED (root signature invalid) | V3, V4, V7 |
| E5-C8 | Bypass: delete `trust_log.jsonl`, clear the index flag | FAILED | FAILED (log missing, fail closed) | V3, V4, V7 |

What remains trusted is what the threat model always declared trusted: the keys directory (root private key and pin), the policy and the verifier. Revocation is still local to one organisation's log; publishing the records to a shared transparency log (Rekor-style) is future work.

## Scenario G — Untrusted external model source (Experiment 7, v0.3)

`python -m attacks.run_all --only G` · script `attacks/scenario_g_untrusted_source.py` · design in `chainguard/external.py`.

**Design.** Two kinds of base model are kept strictly apart:

| | Internal trained base model | External published base model |
| --- | --- | --- |
| type / stage | `base_model` / `stage2_training` | `external_base_model` / `stage2_external_import` |
| signer | our `training_pipeline` key | an outside publisher's key, role `model_publisher` (we hold only its public key) |
| parents | a `dataset` is **required** (rule unchanged) | none: provenance ends at the publisher's identity |
| how it enters | `registry.register` | `import_external_model` (refuses unsigned or malformed input) |

The training key may not sign the external stage, and the publisher key may not sign the internal stage (V4), so an internal model cannot be relabelled "external" to escape the dataset rule. A fine-tuned model needs a dataset parent **and** one base model of either kind (`required_one_of` in `config/policy.yaml`).

| Variant | Situation | Expected | Observed (v0.3 run) | Checks |
| --- | --- | --- | --- | --- |
| E7-A | Trusted, registered publisher signs the model | VERIFIED | VERIFIED, labelled EXTERNAL | — |
| E7-A2 | Fine-tuned on it, sent to the gateway | VERIFIED | VERIFIED, deployed | — |
| E7-B | Unknown / unregistered publisher key | FAILED | FAILED | V3, V4 |
| E7-C | Trusted model modified after signing (one bit) | FAILED | FAILED | V1 |
| E7-D1 | Unsigned model, no manifest | REFUSED | REFUSED at import, nothing stored | — |
| E7-D2 | Manifest with its signature stripped | REFUSED | REFUSED at import, nothing stored | — |
| E7-E | Trusted publisher's key revoked after import | FAILED | FAILED | V4 |
| E7-E2 | Model fine-tuned from it, after the revocation | FAILED | FAILED, **blocked** | V6 |
| E7-F | **Limitation:** trusted publisher signs a backdoored model | VERIFIED | VERIFIED; clean accuracy 93.3 %, backdoor success rate 100 % (clean reference model: 0 %) | — |

E7-F is the external-source version of Scenario E2: a valid signature proves **who** published the model and that it was not modified, not that it is safe. In E7-F the publisher's model was trained from scratch on 8 % corner-trigger poison, which is why its attack success rate is higher than E2's (where clean fine-tuning partly weakened the backdoor).

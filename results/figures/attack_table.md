| Scenario | Variant | Attack | Expected | Observed | Checks | Detection (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| A | A0 | Control: untouched signed dataset | VERIFIED | VERIFIED | - | 4.16 |
| A | A1 | Flip labels of 5 signed rows | FAILED | FAILED | V1, V2 | 5.38 |
| A | A2 | Downstream impact on the final model | FAILED | FAILED | V6 | 10.64 |
| A | A3 | Append one injected row | FAILED | FAILED | V1, V2 | 5.64 |
| A | A4 | One trailing space on one line | FAILED | FAILED | V1, V2 | 5.12 |
| B | B0 | Control: legitimate fine-tuned model | VERIFIED | VERIFIED | - | 9.64 |
| B | B1 | Replace with a different model | FAILED | FAILED | V1 | 9.77 |
| B | B2 | Nudge one weight by 1e-6 | FAILED | FAILED | V1 | 11.04 |
| B | B3 | Same weights re-saved as pickle | FAILED | FAILED | V1 | 10.33 |
| C | C0 | Control: intact chain | VERIFIED | VERIFIED | - | 5.55 |
| C | C1 | Delete the parent dataset record | FAILED | FAILED | V5, V8 | 2.66 |
| C | C2 | Re-sign a modified parent (history rewrite) | FAILED | FAILED | V5 | 5.18 |
| C | C3 | Edit parent link without re-signing | FAILED | FAILED | V3 | 4.82 |
| C | C4 | Model with no dataset ancestry | FAILED | FAILED | V8 | 1.98 |
| D | D0 | Control: valid signature | VERIFIED | VERIFIED | - | 11.92 |
| D | D1 | Corrupt one bit of the signature | FAILED | FAILED | V3 | 10.44 |
| D | D2 | Replay a signature from another manifest | FAILED | FAILED | V3 | 14.27 |
| D | D3 | Sign with an unregistered key | FAILED | FAILED | V3, V4 | 8.88 |
| D | D4 | Signature by a revoked key | FAILED | FAILED | V4, V6 | 9.28 |
| D | D5 | Trusted key used outside its role | FAILED | FAILED | V4 | 9.24 |
| D | D6 | Malformed signature encoding | FAILED | FAILED | V3 | 10.19 |
| E | E0 | Clean baseline | VERIFIED | VERIFIED | - | 9.65 |
| E | E1 | Poison injected after signing | FAILED | FAILED | V6 | 10.32 |
| E | E2 | Poison before signing, no content checks | VERIFIED | VERIFIED | - | 10.52 |
| E | E3 | Poison before signing, content checks on | WARNING | WARNING | V9 | 9.18 |
| E | E4 | Adaptive attacker evades content checks | VERIFIED | VERIFIED | - | 9.24 |
| F | E5-0 | Control: nothing revoked, gateway deploys | VERIFIED | VERIFIED | - | 9.47 |
| F | E5-A1 | Revoke the base model -> descendant fails | FAILED | FAILED | V6, V7 | 14.12 |
| F | E5-A2 | Revoked ancestor -> deployment BLOCKED | FAILED | FAILED | V6, V7 | 14.27 |
| F | E5-B1 | Revoke the training_pipeline key -> its models fail | FAILED | FAILED | V4, V6 | 14.11 |
| F | E5-B2 | Dataset signed by another role still verifies | VERIFIED | VERIFIED | - | 5.45 |
| F | E5-C1 | Bypass: delete the revoked artifact's index row | FAILED | FAILED | V7 | 10.80 |
| F | E5-C2 | Bypass: delete the revoked key from the index | FAILED | FAILED | V4, V6 | 8.85 |
| F | E5-C3 | Bypass: overwrite cached status with VERIFIED | FAILED | FAILED | V6, V7 | 7.55 |
| F | E5-C4 | Bypass: un-revoke by editing the index (v0.3 limitation) | FAILED | FAILED | V6, V7 | 8.76 |
| F | E5-C5 | Bypass: rogue key inserted into the index signs a model | FAILED | FAILED | V3, V4 | 7.22 |
| F | E5-C6 | Bypass: truncate the trust log (rollback) | FAILED | FAILED | V3, V4, V6, V7 | 5.93 |
| F | E5-C7 | Bypass: edit a trust-log record in place | FAILED | FAILED | V3, V4, V6, V7 | 7.25 |
| F | E5-C8 | Bypass: delete the trust log | FAILED | FAILED | V3, V4, V6, V7 | 5.63 |
| G | E7-A | Trusted registered publisher signs the model | VERIFIED | VERIFIED | - | 2.39 |
| G | E7-A2 | Fine-tuned on the trusted external model, deployed | VERIFIED | VERIFIED | - | 6.39 |
| G | E7-B | Unknown / unregistered publisher | FAILED | FAILED | V3, V4 | 2.19 |
| G | E7-C | Trusted publisher's model modified after signing | FAILED | FAILED | V1 | 2.13 |
| G | E7-D1 | Unsigned external model (no manifest) | REFUSED | REFUSED | - | 1.62 |
| G | E7-D2 | Manifest with its signature stripped | REFUSED | REFUSED | - | 1.59 |
| G | E7-E | Trusted publisher key later revoked | FAILED | FAILED | V4 | 1.95 |
| G | E7-E2 | Model fine-tuned from it, after revocation | FAILED | FAILED | V6 | 7.64 |
| G | E7-F | LIMITATION: trusted publisher signs a backdoor | VERIFIED | VERIFIED | - | 2.23 |

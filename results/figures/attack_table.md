| Scenario | Variant | Attack | Expected | Observed | Checks | Detection (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| A | A0 | Control: untouched signed dataset | VERIFIED | VERIFIED | - | 5.44 |
| A | A1 | Flip labels of 5 signed rows | FAILED | FAILED | V1, V2 | 7.42 |
| A | A2 | Downstream impact on the final model | FAILED | FAILED | V6 | 14.52 |
| A | A3 | Append one injected row | FAILED | FAILED | V1, V2 | 7.50 |
| A | A4 | One trailing space on one line | FAILED | FAILED | V1, V2 | 7.53 |
| B | B0 | Control: legitimate fine-tuned model | VERIFIED | VERIFIED | - | 9.93 |
| B | B1 | Replace with a different model | FAILED | FAILED | V1 | 15.07 |
| B | B2 | Nudge one weight by 1e-6 | FAILED | FAILED | V1 | 10.39 |
| B | B3 | Same weights re-saved as pickle | FAILED | FAILED | V1 | 10.75 |
| C | C0 | Control: intact chain | VERIFIED | VERIFIED | - | 5.98 |
| C | C1 | Delete the parent dataset record | FAILED | FAILED | V5, V8 | 2.71 |
| C | C2 | Re-sign a modified parent (history rewrite) | FAILED | FAILED | V5 | 5.46 |
| C | C3 | Edit parent link without re-signing | FAILED | FAILED | V3 | 7.49 |
| C | C4 | Model with no dataset ancestry | FAILED | FAILED | V8 | 2.10 |
| D | D0 | Control: valid signature | VERIFIED | VERIFIED | - | 9.44 |
| D | D1 | Corrupt one bit of the signature | FAILED | FAILED | V3 | 9.87 |
| D | D2 | Replay a signature from another manifest | FAILED | FAILED | V3 | 10.55 |
| D | D3 | Sign with an unregistered key | FAILED | FAILED | V3, V4 | 9.41 |
| D | D4 | Signature by a revoked key | FAILED | FAILED | V4, V6 | 10.14 |
| D | D5 | Trusted key used outside its role | FAILED | FAILED | V4 | 10.26 |
| D | D6 | Malformed signature encoding | FAILED | FAILED | V3 | 13.79 |
| E | E0 | Clean baseline | VERIFIED | VERIFIED | - | 11.08 |
| E | E1 | Poison injected after signing | FAILED | FAILED | V6 | 10.58 |
| E | E2 | Poison before signing, no content checks | VERIFIED | VERIFIED | - | 13.50 |
| E | E3 | Poison before signing, content checks on | WARNING | WARNING | V9 | 12.86 |
| E | E4 | Adaptive attacker evades content checks | VERIFIED | VERIFIED | - | 10.72 |
| F | E5-0 | Control: nothing revoked, gateway deploys | VERIFIED | VERIFIED | - | 13.95 |
| F | E5-A1 | Revoke the base model -> descendant fails | FAILED | FAILED | V6, V7 | 10.62 |
| F | E5-A2 | Revoked ancestor -> deployment BLOCKED | FAILED | FAILED | V6, V7 | 10.43 |
| F | E5-B1 | Revoke the training_pipeline key -> its models fail | FAILED | FAILED | V4, V6 | 10.79 |
| F | E5-B2 | Dataset signed by another role still verifies | VERIFIED | VERIFIED | - | 3.87 |
| F | E5-C1 | Bypass: delete the revoked artifact's index row | FAILED | FAILED | V7 | 7.19 |
| F | E5-C2 | Bypass: delete the revoked key from the index | FAILED | FAILED | V4, V6 | 7.00 |
| F | E5-C3 | Bypass: overwrite cached status with VERIFIED | FAILED | FAILED | V6, V7 | 6.92 |
| F | E5-C4 | Bypass: un-revoke by editing the index (v0.3 limitation) | FAILED | FAILED | V6, V7 | 6.70 |
| F | E5-C5 | Bypass: rogue key inserted into the index signs a model | FAILED | FAILED | V3, V4 | 6.82 |
| F | E5-C6 | Bypass: truncate the trust log (rollback) | FAILED | FAILED | V3, V4, V6, V7 | 5.29 |
| F | E5-C7 | Bypass: edit a trust-log record in place | FAILED | FAILED | V3, V4, V6, V7 | 6.16 |
| F | E5-C8 | Bypass: delete the trust log | FAILED | FAILED | V3, V4, V6, V7 | 5.10 |
| G | E7-A | Trusted registered publisher signs the model | VERIFIED | VERIFIED | - | 2.29 |
| G | E7-A2 | Fine-tuned on the trusted external model, deployed | VERIFIED | VERIFIED | - | 6.23 |
| G | E7-B | Unknown / unregistered publisher | FAILED | FAILED | V3, V4 | 1.71 |
| G | E7-C | Trusted publisher's model modified after signing | FAILED | FAILED | V1 | 1.76 |
| G | E7-D1 | Unsigned external model (no manifest) | REFUSED | REFUSED | - | 1.79 |
| G | E7-D2 | Manifest with its signature stripped | REFUSED | REFUSED | - | 1.91 |
| G | E7-E | Trusted publisher key later revoked | FAILED | FAILED | V4 | 2.46 |
| G | E7-E2 | Model fine-tuned from it, after revocation | FAILED | FAILED | V6 | 6.03 |
| G | E7-F | LIMITATION: trusted publisher signs a backdoor | VERIFIED | VERIFIED | - | 2.16 |

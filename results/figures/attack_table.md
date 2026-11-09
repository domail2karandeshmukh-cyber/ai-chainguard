| Scenario | Variant | Attack | Expected | Observed | Checks | Detection (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| A | A0 | Control: untouched signed dataset | VERIFIED | VERIFIED | - | 3.28 |
| A | A1 | Flip labels of 5 signed rows | FAILED | FAILED | V1, V2 | 4.47 |
| A | A2 | Downstream impact on the final model | FAILED | FAILED | V6 | 10.79 |
| A | A3 | Append one injected row | FAILED | FAILED | V1, V2 | 4.76 |
| A | A4 | One trailing space on one line | FAILED | FAILED | V1, V2 | 4.14 |
| B | B0 | Control: legitimate fine-tuned model | VERIFIED | VERIFIED | - | 9.20 |
| B | B1 | Replace with a different model | FAILED | FAILED | V1 | 7.84 |
| B | B2 | Nudge one weight by 1e-6 | FAILED | FAILED | V1 | 7.58 |
| B | B3 | Same weights re-saved as pickle | FAILED | FAILED | V1 | 8.87 |
| C | C0 | Control: intact chain | VERIFIED | VERIFIED | - | 4.71 |
| C | C1 | Delete the parent dataset record | FAILED | FAILED | V5, V8 | 1.71 |
| C | C2 | Re-sign a modified parent (history rewrite) | FAILED | FAILED | V5 | 4.87 |
| C | C3 | Edit parent link without re-signing | FAILED | FAILED | V3 | 4.18 |
| C | C4 | Model with no dataset ancestry | FAILED | FAILED | V8 | 1.66 |
| D | D0 | Control: valid signature | VERIFIED | VERIFIED | - | 8.83 |
| D | D1 | Corrupt one bit of the signature | FAILED | FAILED | V3 | 9.48 |
| D | D2 | Replay a signature from another manifest | FAILED | FAILED | V3 | 8.70 |
| D | D3 | Sign with an unregistered key | FAILED | FAILED | V3, V4 | 8.44 |
| D | D4 | Signature by a revoked key | FAILED | FAILED | V4, V6 | 9.00 |
| D | D5 | Trusted key used outside its role | FAILED | FAILED | V4 | 9.29 |
| D | D6 | Malformed signature encoding | FAILED | FAILED | V3 | 14.05 |
| E | E0 | Clean baseline | VERIFIED | VERIFIED | - | 9.03 |
| E | E1 | Poison injected after signing | FAILED | FAILED | V6 | 9.92 |
| E | E2 | Poison before signing, no content checks | VERIFIED | VERIFIED | - | 9.27 |
| E | E3 | Poison before signing, content checks on | WARNING | WARNING | V9 | 9.02 |
| E | E4 | Adaptive attacker evades content checks | VERIFIED | VERIFIED | - | 8.95 |
| F | E5-0 | Control: nothing revoked, gateway deploys | VERIFIED | VERIFIED | - | 8.79 |
| F | E5-A1 | Revoke the base model -> descendant fails | FAILED | FAILED | V6, V7 | 9.88 |
| F | E5-A2 | Revoked ancestor -> deployment BLOCKED | FAILED | FAILED | V6, V7 | 9.47 |
| F | E5-B1 | Revoke the training_pipeline key -> its models fail | FAILED | FAILED | V4, V6 | 9.78 |
| F | E5-B2 | Dataset signed by another role still verifies | VERIFIED | VERIFIED | - | 3.37 |
| F | E5-C1 | Bypass: delete the revoked artifact's index row | FAILED | FAILED | V7 | 7.03 |
| F | E5-C2 | Bypass: delete the revoked key from the trust store | FAILED | FAILED | V3, V4, V6 | 6.42 |
| F | E5-C3 | Bypass: overwrite cached status with VERIFIED | FAILED | FAILED | V6, V7 | 6.71 |
| F | E5-C4 | LIMITATION: un-revoke by editing the trusted index | VERIFIED | VERIFIED | - | 6.56 |
| G | E7-A | Trusted registered publisher signs the model | VERIFIED | VERIFIED | - | 1.63 |
| G | E7-A2 | Fine-tuned on the trusted external model, deployed | VERIFIED | VERIFIED | - | 6.34 |
| G | E7-B | Unknown / unregistered publisher | FAILED | FAILED | V3, V4 | 1.33 |
| G | E7-C | Trusted publisher's model modified after signing | FAILED | FAILED | V1 | 1.77 |
| G | E7-D1 | Unsigned external model (no manifest) | REFUSED | REFUSED | - | 2.21 |
| G | E7-D2 | Manifest with its signature stripped | REFUSED | REFUSED | - | 1.76 |
| G | E7-E | Trusted publisher key later revoked | FAILED | FAILED | V4 | 1.87 |
| G | E7-E2 | Model fine-tuned from it, after revocation | FAILED | FAILED | V6 | 6.01 |
| G | E7-F | LIMITATION: trusted publisher signs a backdoor | VERIFIED | VERIFIED | - | 1.95 |

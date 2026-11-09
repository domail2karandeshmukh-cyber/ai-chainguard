| Scenario | Variant | Attack | Expected | Observed | Checks | Detection (ms) |
| --- | --- | --- | --- | --- | --- | --- |
| A | A0 | Control: untouched signed dataset | VERIFIED | VERIFIED | - | 5.26 |
| A | A1 | Flip labels of 5 signed rows | FAILED | FAILED | V1, V2 | 5.51 |
| A | A2 | Downstream impact on the final model | FAILED | FAILED | V6 | 10.22 |
| A | A3 | Append one injected row | FAILED | FAILED | V1, V2 | 4.40 |
| A | A4 | One trailing space on one line | FAILED | FAILED | V1, V2 | 5.40 |
| B | B0 | Control: legitimate fine-tuned model | VERIFIED | VERIFIED | - | 9.68 |
| B | B1 | Replace with a different model | FAILED | FAILED | V1 | 10.11 |
| B | B2 | Nudge one weight by 1e-6 | FAILED | FAILED | V1 | 9.29 |
| B | B3 | Same weights re-saved as pickle | FAILED | FAILED | V1 | 8.98 |
| C | C0 | Control: intact chain | VERIFIED | VERIFIED | - | 7.79 |
| C | C1 | Delete the parent dataset record | FAILED | FAILED | V5, V8 | 2.49 |
| C | C2 | Re-sign a modified parent (history rewrite) | FAILED | FAILED | V5 | 5.06 |
| C | C3 | Edit parent link without re-signing | FAILED | FAILED | V3 | 4.02 |
| C | C4 | Model with no dataset ancestry | FAILED | FAILED | V8 | 1.67 |
| D | D0 | Control: valid signature | VERIFIED | VERIFIED | - | 9.44 |
| D | D1 | Corrupt one bit of the signature | FAILED | FAILED | V3 | 9.04 |
| D | D2 | Replay a signature from another manifest | FAILED | FAILED | V3 | 9.63 |
| D | D3 | Sign with an unregistered key | FAILED | FAILED | V3, V4 | 9.32 |
| D | D4 | Signature by a revoked key | FAILED | FAILED | V4, V6 | 9.11 |
| D | D5 | Trusted key used outside its role | FAILED | FAILED | V4 | 11.26 |
| D | D6 | Malformed signature encoding | FAILED | FAILED | V3 | 9.09 |
| E | E0 | Clean baseline | VERIFIED | VERIFIED | - | 8.63 |
| E | E1 | Poison injected after signing | FAILED | FAILED | V6 | 11.91 |
| E | E2 | Poison before signing, no content checks | VERIFIED | VERIFIED | - | 10.54 |
| E | E3 | Poison before signing, content checks on | WARNING | WARNING | V9 | 9.01 |
| E | E4 | Adaptive attacker evades content checks | VERIFIED | VERIFIED | - | 8.86 |

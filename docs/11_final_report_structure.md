# Final report structure (~30 pages)

*Page budget in brackets. Figures and tables referenced are produced by `scripts/make_figures.py`.*

**Front matter** [2] — title page, abstract (200 words), table of contents, list of figures.

1. **Introduction** [2] — context, research question, contributions (3 bullets), report outline.
2. **Background** [3] — supply-chain attacks on AI; hashing, signatures, Merkle trees; integrity vs semantic trust.
3. **State of the art** [4] — signing and Sigstore/OMS, SLSA and in-toto, model cards and ML-BOMs, backdoor defences; comparative table (`03_comparative_table.md`); gap.
4. **Threat model** [3] — assets, actors, trust boundaries diagram, threat table, residual risks; AI vs software supply chains.
5. **Design** [4] — architecture diagram, manifest design, hash-linked provenance and release root, roles and policy, verification checks V0–V9, status semantics; design decisions and alternatives table.
6. **Implementation** [3] — code organisation, crypto details (canonical JSON, Ed25519, RFC 6962 Merkle), TOCTOU-safe loading, ML pipeline, API/dashboard, Docker/CI. Prototype-only choices.
7. **Evaluation** [6]
   - 7.1 Methodology (scenarios, metrics, environment)
   - 7.2 Detection results A–D (Figure: attack outcomes; table)
   - 7.3 Scenario E: strength and limits (Figure: backdoor ASR; table E0–E4)
   - 7.4 Performance (Figure: cost vs size; Merkle cost; overhead vs training)
   - 7.5 Threats to validity (small dataset/model, single machine, heuristic tuned by the defender)
8. **Discussion** [2] — what attestation guarantees; what it cannot; how semantic checks fit; production gaps (KMS, transparency log, TEE).
9. **Conclusion and future work** [1] — Sigstore/Rekor anchoring, ML-DSA migration, trigger-agnostic detection, larger models, ML-BOM export.
10. **Project management** [1] — roadmap vs actual, team roles, lessons learned.

**References** [1] · **Appendices** [not counted] — manifest example, API reference, test list, full attack results, weekly reports.

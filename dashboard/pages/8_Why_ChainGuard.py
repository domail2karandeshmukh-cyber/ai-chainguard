"""Why AI-ChainGuard: positioning against existing supply-chain tools, honestly."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dashboard.api_client import page_header  # noqa: E402

page_header("Why AI-ChainGuard", "What existing tools already do, what they leave open for AI artifacts, and "
            "where this project sits")

st.markdown(
    "<div class='cg-note'><b>One sentence.</b> Existing tools sign <i>one artifact</i> (cosign, OpenSSF Model "
    "Signing), describe it (model cards, ML-BOM) or attest <i>software builds</i> (SLSA, in-toto). AI-ChainGuard "
    "links datasets, base models, fine-tuned models and deployments into <b>one verifiable chain with a role "
    "policy, revocation and a deployment gate</b>, speaks the ecosystem's formats (in-toto / DSSE / SLSA export), "
    "and <b>measures</b> where cryptographic integrity stops: a signed model is not a safe model.</div>",
    unsafe_allow_html=True)

st.subheader("Side by side")
rows = [
    # tool, scope, chain, policy/roles, revocation, deploy gate, content, AI-specific, infra
    ["Plain checksums (SHA-256 files on a hub)", "one file", "no", "no", "no", "no", "no", "no", "none"],
    ["Sigstore / cosign", "one artifact (OCI, blob)", "no", "identity policies", "via log + cert expiry", "admission controllers (containers)", "no", "no", "Fulcio, Rekor, OIDC"],
    ["OpenSSF Model Signing (model_signing)", "a model directory", "no", "signer identity", "Sigstore ecosystem", "no", "no", "yes (model files)", "Sigstore or PKI"],
    ["in-toto attestations + layouts", "steps of a pipeline", "yes (layout links steps)", "functionaries per step", "key revocation in layout", "final product verification", "no", "no", "none required"],
    ["SLSA provenance (v1)", "a build", "build inputs recorded", "builder identity", "no", "policy engines (external)", "no", "no", "hardened builder"],
    ["Hugging Face safetensors", "model file format", "no", "no", "no", "no", "no (safe loading only)", "yes", "none"],
    ["Model cards / datasheets, ML-BOM", "description, inventory", "inventory only", "no", "no", "no", "no", "yes", "none"],
    ["MLflow / DVC registries", "versions and lineage metadata", "metadata lineage", "RBAC (platform)", "stage transitions", "stage transitions", "no", "yes", "a server / remote"],
    ["Backdoor scanners (Neural Cleanse, STRIP, …)", "model behaviour", "no", "no", "no", "no", "partial, heuristic", "yes", "compute"],
    ["AI-ChainGuard (this project)", "dataset → base → fine-tune → deployment", "yes, hash-linked signed parents (V5/V6)", "role per stage (V4/V8)", "signed, pinned log; propagates (V7)", "yes: verify once, safe load, smoke test, signed record", "partial: V9 heuristics, WARNING only", "yes (Merkle rows, external publishers)", "none (files + SQLite index)"],
]
cols = ["Approach", "Scope", "Links stages", "Who may sign what", "Revocation", "Deployment gate",
        "Detects poisoned content", "AI-specific", "Infrastructure"]
df = pd.DataFrame(rows, columns=cols)
st.dataframe(df, hide_index=True, width="stretch", height=420)
st.caption("Vendor and project capabilities as documented by them (Nov 2026); 'no' means not a goal of that tool, "
           "not a defect. No approach in the content column says 'yes': that is the point of the project.")

st.subheader("What is different, concretely")
c1, c2 = st.columns(2)
with c1:
    st.markdown(
        "**1. The chain, not the file.** Parent *manifest digests* are inside each child's signed payload, so "
        "rewriting an ancestor breaks every descendant (Scenario C). A re-signed, modified parent fails.\n\n"
        "**2. Roles are enforced by the verifier (V4/V8), not by convention.** The training key cannot sign a "
        "dataset; an external publisher cannot be impersonated by relabelling an internal model.\n\n"
        "**3. Revocation is a signed, pinned, append-only log (v0.4).** Editing the index, truncating, editing or "
        "deleting the log all fail closed (Scenario F, E5-C4 to C8).\n\n"
        "**4. A deployment gate that verifies once.** Full chain verification, TOCTOU-safe read, refusal of "
        "pickle formats, smoke test, signed deployment record binding the trust-log head; inference then costs "
        "nothing extra (benchmark D vs A).")
with c2:
    st.markdown(
        "**5. Row-level evidence for data.** A dataset Merkle root localises which lines changed (Scenario A), "
        "which a file hash cannot.\n\n"
        "**6. Interoperable, not isolated.** Any attestation exports as an in-toto Statement in a DSSE envelope, "
        "with a ChainGuard or SLSA Provenance v1 predicate (`export`, `GET /artifacts/{id}/attestation`).\n\n"
        "**7. Honest about the boundary.** Experiments 6 and 7 *measure* that signed poison verifies (77 % and "
        "100 % backdoor success behind a VERIFIED status) and that heuristics only warn. The platform never "
        "upgrades 'signed' to 'safe'.\n\n"
        "**8. Reproducible.** 168 automated tests, 48 attack/control variants, benchmark and figures regenerated "
        "by scripts; every number in the reports and the paper comes from `results/`.")

st.subheader("What it is not (yet)")
st.markdown(
    "- Not a public transparency log: the trust log is single-writer and local; publishing to Rekor-style "
    "infrastructure is future work.\n"
    "- Not keyless: long-lived Ed25519 keys in files (production: KMS/HSM or Sigstore Fulcio).\n"
    "- Not a content-safety tool: V9 heuristics are evidence, not proof; an adaptive attacker evades them (E4).\n"
    "- Not production-hardened: no API authentication or TLS; Python-only canonical JSON (RFC 8785 for multi-language).")

st.caption("References and the full comparative table: docs/02_state_of_the_art.md, docs/03_comparative_table.md "
           "and the IEEE paper in paper/.")

"""External (third-party) models: publisher trust, imports and quarantine (Experiment 7)."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dashboard.api_client import ApiError, get, guard, page_header, post, report_table, status_badge  # noqa: E402

page_header("External models", "Experiment 7 · a model from an outside publisher enters the chain only with a "
            "valid signature from a registered, unrevoked publisher key")

MODES = {
    "trusted": ("✅ Trusted publisher", "The hub's public key is registered as model_publisher; the model verifies "
                "(labelled EXTERNAL: origin and integrity, not safety)."),
    "unknown": ("⛔ Unknown publisher", "Valid signature, but from a key nobody trusted → FAILED V3/V4 and quarantined."),
    "tampered": ("⛔ Tampered in transit", "Trusted publisher, one bit flipped after signing → FAILED V1."),
    "unsigned": ("🚫 Unsigned model", "No manifest at all → REFUSED at import, nothing stored."),
}

if guard():
    st.markdown(
        "<div class='cg-note'>Internal base models must descend from an attested dataset. An external base model "
        "has no internal lineage: its provenance <b>ends at the publisher's identity</b>, and only a key registered "
        "with the <code>model_publisher</code> role may sign it. A fine-tuned model may build on either kind.</div>",
        unsafe_allow_html=True)

    st.subheader("Simulate a publisher (demo)")
    cols = st.columns(4)
    outcome = None
    for col, (mode, (label, help_text)) in zip(cols, MODES.items(), strict=True):
        if col.button(label, help=help_text, width="stretch"):
            try:
                with st.spinner("Publishing, importing and verifying..."):
                    outcome = post("/external/demo", {"mode": mode})
            except ApiError as exc:
                st.error(str(exc))
    if outcome:
        st.markdown(status_badge(outcome["outcome"], "1.4rem") + f"&nbsp; **{outcome['publisher']}** · "
                    f"{MODES[outcome['mode']][1]}", unsafe_allow_html=True)
        if outcome["outcome"] == "REFUSED":
            st.warning(f"Import refused: {outcome['reason']}  ·  nothing was stored.")
        else:
            rep = outcome["report"]
            if outcome.get("quarantined"):
                st.error("Stored as QUARANTINED evidence: it cannot be used as a parent and the gateway blocks it.")
            st.dataframe(report_table(rep), hide_index=True, width="stretch")
            if rep.get("external_artifacts"):
                st.info(f"EXTERNAL in chain: {', '.join(rep['external_artifacts'])} — the publisher signature proves "
                        "origin and integrity, not that the model is safe (E7-F).")

    data = get("/external")
    st.subheader("Trusted publishers")
    if data["publishers"]:
        st.dataframe(pd.DataFrame([{"identity": p["identity"], "key id": p["key_id"],
                                    "state": "REVOKED" if p["revoked_at"] else "active",
                                    "trusted since": (p["created_at"] or "")[:19]} for p in data["publishers"]]),
                     hide_index=True, width="stretch")
    else:
        st.caption("No publisher key registered yet.")

    st.subheader("Imported external models")
    if data["models"]:
        df = pd.DataFrame([{"status": m["last_status"] or "not verified", "name": m["artifact_name"],
                            "publisher": m["publisher"], "publisher key trusted": m["publisher_key_trusted"],
                            "size (bytes)": m["size_bytes"], "sha256": m["sha256"][:16] + "…",
                            "id": m["artifact_id"]} for m in data["models"]])

        def color(v: str) -> str:
            return {"VERIFIED": "color:#1f9d55;font-weight:700", "FAILED": "color:#e53e3e;font-weight:700"}.get(v, "")

        st.dataframe(df.style.map(color, subset=["status"]), hide_index=True, width="stretch")
    else:
        st.caption("No external model imported yet.")

    with st.expander("Register a real publisher key / import from the workspace"):
        st.markdown("CLI: `publisher keygen`, `publisher sign`, `keys trust-publisher`, `import-external` — "
                    "API: `POST /external/publishers`, `POST /external/import`.")
        pk = st.text_input("Publisher public key (base64 raw Ed25519)")
        ident = st.text_input("Publisher identity", "release-bot@hub.example")
        if st.button("Trust this publisher key") and pk:
            try:
                r = post("/external/publishers", {"public_key_b64": pk.strip(), "identity": ident.strip()})
                st.success(f"trusted {r['key_id']} as {r['identity']}")
            except ApiError as exc:
                st.error(str(exc))

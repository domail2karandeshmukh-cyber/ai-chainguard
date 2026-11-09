"""AI-ChainGuard dashboard - Overview page.

Run:  streamlit run dashboard/Overview.py      (API running, or CHAINGUARD_STANDALONE=1 to embed it)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dashboard.api_client import ApiError, get, guard, page_header, post, status_badge  # noqa: E402

page_header("AI-ChainGuard", "AI Supply Chain Integrity & Attestation Platform · overview")

if guard():
    health = get("/health")
    artifacts = get("/artifacts")
    events = get("/events", limit=500)

    statuses = [a["last_status"] for a in artifacts]
    c = st.columns(6)
    c[0].metric("Artifacts", len(artifacts))
    c[1].metric("Verified", statuses.count("VERIFIED"))
    c[2].metric("Warning", statuses.count("WARNING"))
    c[3].metric("Failed", statuses.count("FAILED"))
    c[4].metric("Revoked", sum(a["revoked"] for a in artifacts))
    c[5].metric("Critical events", sum(e["severity"] == "critical" for e in events))

    left, right = st.columns([3, 1])
    with right:
        st.markdown("**Workspace**")
        st.code(health["workspace"], language=None)
        tl = health.get("trust_log") or {}
        st.markdown(f"**Trusted signers:** {health['signers']}  ·  **v{health['version']}**")
        if tl:
            st.markdown(("🟢" if tl.get("ok") else "🔴") + f" **Signed trust log:** {tl.get('head_seq', 0)} records"
                        + ("" if tl.get("ok") else f" — {tl.get('error')}"))
        if st.button("Re-verify all artifacts", type="primary", width="stretch", disabled=not artifacts):
            with st.spinner("Verifying every artifact and its chain..."):
                for a in artifacts:
                    post(f"/verify/{a['artifact_id']}", context="dashboard")
            st.rerun()
        if not artifacts and st.button("Build the attested chain now", width="stretch",
                                       help="Runs the four-stage pipeline in this workspace (about 10 s on CPU)"):
            with st.spinner("Stage 1-4: datasets, base model, fine-tuning, deployment gateway..."):
                try:
                    out = post("/demo/pipeline")
                    st.success("Pipeline complete: " + (out["deployment"] or {}).get("status", "done"))
                except ApiError as exc:
                    st.error(str(exc))
            st.rerun()

    with left:
        st.subheader("Registered artifacts")
        if not artifacts:
            st.info("No artifacts yet. Run `python -m ml_pipeline.run_pipeline`, or click **Build the attested "
                    "chain now** on the right.")
        else:
            df = pd.DataFrame([{
                "status": a["last_status"] or "not verified",
                "stage": a["pipeline_stage"], "type": a["artifact_type"], "name": a["artifact_name"],
                "version": a["version"], "size (bytes)": a["size_bytes"],
                "revoked": "yes" if a["revoked"] else "", "sha256": a["sha256"][:16] + "…",
                "id": a["artifact_id"],
            } for a in artifacts])

            def color(v: str) -> str:
                return {"VERIFIED": "color:#1f9d55;font-weight:700", "WARNING": "color:#d69e2e;font-weight:700",
                        "FAILED": "color:#e53e3e;font-weight:700"}.get(v, "")

            st.dataframe(df.style.map(color, subset=["status"]), hide_index=True, width="stretch")

    st.subheader("Latest security events")
    crit = [e for e in events if e["severity"] != "info"][:8]
    if not crit:
        st.success("No warning or critical events.")
    for e in crit:
        badge = status_badge("FAILED" if e["severity"] == "critical" else "WARNING", "0.75rem")
        st.markdown(f"{badge} `{e['ts'][:19]}` **{e['event_type']}** — {e['message']}", unsafe_allow_html=True)

    with st.expander("What do VERIFIED / WARNING / FAILED mean?"):
        st.markdown(
            "- **VERIFIED** — every cryptographic and policy check passed and no content check flagged the "
            "artifact or its ancestors. It means *exactly what trusted signers attested, through an intact "
            "chain*; it does **not** prove the model is safe.\n"
            "- **WARNING** — integrity is intact, but a pre-attestation semantic check flagged the content "
            "(here or upstream). The gateway blocks deployment by default.\n"
            "- **FAILED** — bytes, signature, signer trust, provenance links, revocation or policy are broken.")

"""Verify an artifact (checks V0-V9) and push it through the deployment gateway."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dashboard.api_client import (  # noqa: E402
    OUTCOME_ICON,
    ApiError,
    artifact_label,
    get,
    guard,
    page_header,
    post,
    status_badge,
)

page_header("Verify artifact", "Full chain verification: hash, Merkle, signature, signer trust, "
            "provenance, revocation, policy, semantic flags")


def show_report(rep: dict) -> None:
    st.markdown(status_badge(rep["status"], "1.6rem"), unsafe_allow_html=True)
    st.markdown(f"**{rep['artifact_name']}** · {rep['artifact_type']} · {rep['pipeline_stage']} · "
                f"verified in {rep['duration_ms']:.1f} ms")
    df = pd.DataFrame([{"check": c["check_id"], "name": c["name"], "result": OUTCOME_ICON[c["outcome"]],
                        "message": c["message"]} for c in rep["checks"]])
    st.dataframe(df, hide_index=True, width="stretch")
    if rep["ancestors"]:
        st.markdown("**Ancestors verified recursively**")
        st.dataframe(pd.DataFrame([{
            "status": a["status"], "name": a["artifact_name"], "type": a["artifact_type"],
            "failed": ", ".join(a["failed_checks"]), "warned": ", ".join(a["warned_checks"]),
            "revoked": "yes" if a["revoked"] else ""} for a in rep["ancestors"]]),
            hide_index=True, width="stretch")
    for c in rep["checks"]:
        if c["outcome"] in ("fail", "warn") and c["details"]:
            with st.expander(f"Evidence for {c['check_id']} · {c['name']}"):
                st.json(c["details"])


if guard():
    artifacts = get("/artifacts")
    if not artifacts:
        st.info("No artifacts registered yet.")
        st.stop()
    options = {artifact_label(a): a for a in artifacts}
    default = next((i for i, a in enumerate(artifacts) if a["artifact_type"] == "finetuned_model"), 0)
    choice = st.selectbox("Artifact", list(options), index=default)
    art = options[choice]

    b1, b2, b3 = st.columns(3)
    verify_clicked = b1.button("Verify now", type="primary", width="stretch")
    deployable = art["artifact_type"] in ("finetuned_model", "base_model")
    deploy_clicked = b2.button("Send to deployment gateway", disabled=not deployable, width="stretch")
    with b3.popover("Revoke…", width="stretch"):
        reason = st.text_input("Reason", "suspected compromise")
        if st.button("Confirm revocation"):
            post(f"/artifacts/{art['artifact_id']}/revoke", {"reason": reason})
            st.warning("Artifact revoked. Every descendant now fails V7.")

    try:
        if deploy_clicked:
            with st.spinner("Gateway: verifying chain, loading verified bytes, smoke test..."):
                d = post(f"/deploy/{art['artifact_id']}", {"environment": "staging"})
            if d["deployed"]:
                st.success(f"DEPLOYED to staging. Release root `{d['release_root']}`")
                st.json(d["smoke_test"])
            else:
                st.error(f"BLOCKED: {d['reason']}")
            if d.get("report"):
                show_report(d["report"])
        elif verify_clicked or st.session_state.get("auto_verify", True):
            show_report(post(f"/verify/{art['artifact_id']}", context="dashboard"))
    except ApiError as exc:
        st.error(str(exc))

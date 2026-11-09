"""Attack lab: tamper live with your own workspace, or run the scripted scenarios A-G."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dashboard.api_client import (  # noqa: E402
    ApiError,
    artifact_label,
    get,
    guard,
    page_header,
    post,
    status_badge,
)

page_header("Attack lab", "Live tampering on this workspace, and scripted scenarios in isolated sandboxes")

SCENARIOS = {
    "A": "Dataset tampering", "B": "Model substitution", "C": "Broken provenance",
    "D": "Invalid signature", "E": "Backdoor / data poisoning (trains models, ~30 s)",
    "F": "Revocation (Exp. 5)", "G": "External model source (Exp. 7)",
}

if guard():
    st.subheader("1 · Live tampering demo")
    st.caption("Modifies the real file of a registered artifact (a backup is kept), then re-verifies it.")
    artifacts = [a for a in get("/artifacts") if a["artifact_type"] != "deployment_record"]
    if artifacts:
        options = {artifact_label(a): a for a in artifacts}
        col1, col2 = st.columns([3, 2])
        art = options[col1.selectbox("Target artifact", list(options))]
        mode = col2.selectbox("Tampering", ["flip_byte", "append_bytes", "flip_label"],
                              help="flip_label only applies to CSV datasets")
        t1, t2, t3 = st.columns(3)
        try:
            if t1.button("Tamper", type="primary", width="stretch"):
                post(f"/demo/tamper/{art['artifact_id']}", {"mode": mode})
                rep = post(f"/verify/{art['artifact_id']}", context="attack-lab")
                st.markdown(status_badge(rep["status"], "1.4rem"), unsafe_allow_html=True)
                for c in rep["checks"]:
                    if c["outcome"] == "fail":
                        st.error(f"{c['check_id']} {c['name']}: {c['message']}")
            if t2.button("Restore original", width="stretch"):
                post(f"/demo/restore/{art['artifact_id']}")
                rep = post(f"/verify/{art['artifact_id']}", context="attack-lab")
                st.markdown(status_badge(rep["status"], "1.4rem"), unsafe_allow_html=True)
            if t3.button("Verify final model", width="stretch"):
                final = next((a for a in get("/artifacts") if a["artifact_type"] == "finetuned_model"), None)
                if final:
                    rep = post(f"/verify/{final['artifact_id']}", context="attack-lab")
                    st.markdown(f"Final model: {status_badge(rep['status'], '1.2rem')}", unsafe_allow_html=True)
                    st.caption(" · ".join(f"{c['check_id']}: {c['message']}" for c in rep["checks"]
                                          if c["outcome"] == "fail") or "chain intact")
        except ApiError as exc:
            st.error(str(exc))
    else:
        st.info("Run the pipeline first to have artifacts to attack.")

    st.divider()
    st.subheader("2 · Scripted attack scenarios")
    st.caption("Each scenario clones a fresh clean chain into a temporary workspace, attacks it and verifies.")
    cols = st.columns(len(SCENARIOS))
    for col, (key, title) in zip(cols, SCENARIOS.items(), strict=True):
        if col.button(f"Run {key}", help=title, width="stretch"):
            with st.spinner(f"Running scenario {key}: {title}"):
                try:
                    post(f"/attacks/{key}")
                except ApiError as exc:
                    st.error(str(exc))

    results = get("/attacks/results")
    if not results:
        st.info("No scenario results yet. Run one above or `python -m attacks.run_all`.")
    for r in results:
        ok = "✅ all as expected" if r["all_as_expected"] else "❌ unexpected outcome"
        with st.expander(f"Scenario {r['scenario']} · {r['title']} — {ok} · ran {r['ran_at']}", expanded=False):
            st.markdown(f"_{r['demonstrates']}_")
            rows = []
            for v in r["variants"]:
                row = {"variant": v["variant"], "attack": v["title"], "expected": v["expected"],
                       "observed": v["observed"], "checks": ", ".join(v["failed_checks"] or v["warned_checks"]),
                       "detect ms": round(v["detection_ms"], 2)}
                if "attack_success_rate" in v["details"]:
                    row["clean acc"] = v["details"]["clean_accuracy"]
                    row["ASR"] = v["details"]["attack_success_rate"]
                    row["deployed"] = v["details"]["deployed"]
                rows.append(row)
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
            if r.get("interpretation"):
                st.info(r["interpretation"])

"""Security events log."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dashboard.api_client import get, guard, page_header  # noqa: E402

page_header("Security events", "Registrations, verification failures, revocations and gateway decisions")

if guard():
    c1, c2 = st.columns([1, 3])
    severity = c1.selectbox("Severity", ["all", "critical", "warning", "info"])
    events = get("/events", limit=1000, severity=None if severity == "all" else severity)
    types = sorted({e["event_type"] for e in events})
    chosen = c2.multiselect("Event types", types, default=types)
    rows = [e for e in events if e["event_type"] in chosen]
    if not rows:
        st.info("No events.")
        st.stop()
    df = pd.DataFrame([{"time": e["ts"][:19].replace("T", " "), "severity": e["severity"],
                        "event": e["event_type"], "artifact": (e["artifact_id"] or "")[:8],
                        "message": e["message"]} for e in rows])

    def color(v: str) -> str:
        return {"critical": "color:#e53e3e;font-weight:700", "warning": "color:#d69e2e;font-weight:700"}.get(v, "")

    st.dataframe(df.style.map(color, subset=["severity"]), hide_index=True, width="stretch", height=520)
    st.bar_chart(df.groupby("event").size().rename("count"), horizontal=True)
    st.download_button("Download CSV", df.to_csv(index=False), "chainguard_events.csv", "text/csv")

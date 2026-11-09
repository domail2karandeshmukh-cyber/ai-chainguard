"""Performance metrics: hashing, signing, verification, training, inference."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dashboard.api_client import get, guard, page_header  # noqa: E402

page_header("Performance metrics", "Every measured operation is stored in the metrics table")

if guard():
    summary = get("/metrics/summary")
    if not summary:
        st.info("No metrics yet.")
        st.stop()
    sdf = pd.DataFrame(summary)
    st.dataframe(sdf, hide_index=True, width="stretch")

    crypto_ops = ["hash", "merkle", "semantic", "sign", "verify_signature", "verify_full"]
    st.subheader("Security operations (mean ms)")
    st.bar_chart(sdf[sdf.operation.isin(crypto_ops)].set_index("operation")["mean_ms"])

    raw = pd.DataFrame(get("/metrics", limit=10000))
    st.subheader("Hashing time vs artifact size")
    h = raw[(raw.operation == "hash") & raw.size_bytes.notna()]
    if not h.empty:
        st.scatter_chart(h, x="size_bytes", y="duration_ms", x_label="artifact size (bytes)",
                         y_label="SHA-256 time (ms)")

    st.subheader("Attestation overhead vs. ML work")
    train = raw[raw.operation == "train"].duration_ms.sum()
    attest = raw[raw.operation == "register_total"].duration_ms.sum()
    verify = raw[raw.operation == "verify_full"].duration_ms.sum()
    c = st.columns(3)
    c[0].metric("Training time (total)", f"{train / 1000:.2f} s")
    c[1].metric("Attestation time (total)", f"{attest:.1f} ms",
                f"{100 * attest / train:.2f}% of training" if train else None, delta_color="off")
    c[2].metric("Verification time (total)", f"{verify:.1f} ms")

    st.subheader("Full-chain verification latency over time")
    v = raw[raw.operation == "verify_full"].iloc[::-1].reset_index(drop=True)
    if not v.empty:
        st.line_chart(v["duration_ms"], x_label="verification run", y_label="ms")
    st.download_button("Download raw metrics (CSV)", raw.to_csv(index=False), "chainguard_metrics.csv", "text/csv")

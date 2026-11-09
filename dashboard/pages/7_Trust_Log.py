"""The signed, append-only trust log (v0.4): keys, revocations, and live bypass attempts."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dashboard.api_client import ApiError, get, guard, page_header, post, report_table, status_badge  # noqa: E402

page_header("Trust log", "Who is trusted and what is revoked, as a hash-chained log signed by the root key and "
            "pinned in the trusted keys directory")

ATTACKS = {
    "control": ("Control", "Revoke the base model, change nothing else → the fine-tuned model must FAIL (V6/V7)."),
    "unrevoke_index": ("Un-revoke in SQLite", "The v0.3 limitation E5-C4: clear the revoked flag in the index."),
    "rogue_key": ("Rogue key in the index", "E5-C5: insert the attacker's key as training_pipeline and re-sign a "
                  "substituted model with it."),
    "truncate_log": ("Truncate the log", "E5-C6: delete the last record (the revocation) and clear the index flag."),
    "edit_log": ("Edit a record", "E5-C7: rewrite the revocation record in place, keeping its signature."),
    "delete_log": ("Delete the log", "E5-C8: remove trust_log.jsonl and clear the index flag."),
}

if guard():
    log = get("/trust-log")
    c = st.columns(5)
    c[0].metric("Log status", "VALID" if log["ok"] else "INVALID")
    c[1].metric("Records", log["head_seq"])
    c[2].metric("Trusted keys", log["trusted_keys"])
    c[3].metric("Revoked keys", log["revoked_keys"])
    c[4].metric("Revoked artifacts", log["revoked_artifacts"])
    st.caption(f"root key `{log['root_key_id']}` · head `{log['head_hash'] or ''}` · replayed in {log['verify_ms']:.2f} ms")
    if not log["ok"]:
        st.error(f"⛔ {log['error']}")

    st.markdown(
        "<div class='cg-note'>Until v0.3 the trust store and the revocation flags lived in the SQLite index, so "
        "anyone able to write that file could un-revoke a model (documented limitation E5-C4). Since v0.4 the "
        "verifier replays this log: every record is signed by the <code>release_manager</code> root key and "
        "chained to the previous one, and the pin <code>keys/trust_root.json</code> fixes the last record. "
        "Truncating, editing, deleting or substituting the log, or editing the index, now fails closed.</div>",
        unsafe_allow_html=True)

    if log["entries"]:
        st.subheader("Records")
        rows = []
        for e in log["entries"]:
            s = e["subject"]
            rows.append({"#": e["seq"], "time": (e["ts"] or "")[:19], "action": e["action"],
                         "subject": s.get("artifact_id") or f"{s.get('role', '')} · {s.get('identity', '')}",
                         "key id": s.get("key_id", ""), "reason": e.get("reason") or "",
                         "record hash": e["hash"][7:23] + "…"})
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

    st.subheader("Live bypass attempts (sandbox copy of this workspace)")
    st.caption("Each button copies the workspace, revokes the base model there, applies the attack and verifies the "
               "fine-tuned model. Your real workspace is untouched. Expected: the control FAILS because of the "
               "revocation, and every bypass FAILS too.")
    cols = st.columns(len(ATTACKS))
    result = None
    for col, (mode, (label, help_text)) in zip(cols, ATTACKS.items(), strict=True):
        if col.button(label, help=help_text, width="stretch"):
            try:
                with st.spinner(f"{label}: copying the workspace and verifying..."):
                    result = post("/demo/trustlog-attack", {"mode": mode})
            except ApiError as exc:
                st.error(str(exc))
    if result:
        rep = result["report"]
        st.markdown(status_badge(rep["status"], "1.4rem") + f"&nbsp; **{ATTACKS[result['mode']][0]}** — "
                    f"{result['attack']}", unsafe_allow_html=True)
        tl = result["trust_log"]
        if tl["ok"]:
            st.success(f"Trust log valid · {tl['head_seq']} records · replayed in {tl['verify_ms']:.2f} ms")
        else:
            st.error(f"Trust log rejected: {tl['error']} → verifier fails closed")
        st.dataframe(report_table(rep), hide_index=True, width="stretch")
        if result["events"]:
            st.markdown("**Critical events raised in the sandbox**")
            for ev in result["events"][:8]:
                st.markdown(f"- `{ev['event_type']}` {ev['message']}")

    with st.expander("How this compares"):
        st.markdown(
            "- **TUF** (The Update Framework) pins a root role and protects against rollback with versioned, "
            "signed metadata; the pin + sequence number here plays the same role for one organisation.\n"
            "- **Certificate Transparency / Sigstore Rekor** make a public, Merkle-tree log tamper-evident for "
            "everybody. This log is single-writer and local: the natural next step is to publish its records to "
            "such a shared log so every verifier sees one history.\n"
            "- **What is still trusted:** the keys directory (root private key and the pin), the policy and the "
            "verifier. An attacker who controls those controls everything, as the threat model states.")

"""Provenance chain: the hash-linked artifact graph, coloured by verification status."""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dashboard.api_client import STATUS_COLOR, artifact_label, get, guard, page_header  # noqa: E402

page_header("Provenance chain", "Each edge is a parent manifest digest embedded in the child's signed payload")

STAGE_LABEL = {"stage1_dataset": "Stage 1 · Datasets", "stage2_training": "Stage 2 · Training",
               "stage3_finetune": "Stage 3 · Fine-tuning", "stage4_deployment": "Stage 4 · Deployment"}
SHAPE = {"dataset": "cylinder", "base_model": "box3d", "finetuned_model": "box3d", "deployment_record": "note"}


def dot(graph: dict, focus: str | None) -> str:
    lines = ["digraph G {", 'rankdir=LR; bgcolor="transparent"; nodesep=0.35; ranksep=0.8;',
             'node [style="filled,rounded", fontname="Helvetica", fontsize=11, fontcolor="white"];',
             'edge [color="#94a3b8", fontcolor="#94a3b8", fontsize=9, fontname="Helvetica"];']
    by_stage: dict[str, list[dict]] = {}
    for n in graph["nodes"]:
        by_stage.setdefault(n["stage"], []).append(n)
    for i, (stage, nodes) in enumerate(sorted(by_stage.items())):
        lines.append(f'subgraph cluster_{i} {{ label="{STAGE_LABEL.get(stage, stage)}"; color="#475569"; '
                     'fontcolor="#94a3b8"; style="rounded,dashed";')
        for n in nodes:
            color = "#4a5568" if n["revoked"] else STATUS_COLOR.get(n["status"], STATUS_COLOR[None])
            pen = 3 if n["artifact_id"] == focus else 1
            label = f"{n['name']}\\n{n['type']} v{n['version']}\\n{n['status'] or 'not verified'}"
            if n["revoked"]:
                label += "\\nREVOKED"
            lines.append(f'"{n["artifact_id"]}" [label="{label}", fillcolor="{color}", '
                         f'shape={SHAPE.get(n["type"], "box")}, penwidth={pen}, color="white"];')
        lines.append("}")
    for e in graph["edges"]:
        lines.append(f'"{e["parent"]}" -> "{e["child"]}" [label="{e["relation"]}"];')
    lines.append("}")
    return "\n".join(lines)


if guard():
    graph = get("/graph")
    artifacts = get("/artifacts")
    if not artifacts:
        st.info("No artifacts registered yet.")
        st.stop()
    options = {artifact_label(a): a["artifact_id"] for a in artifacts}
    default = next((i for i, a in enumerate(artifacts) if a["artifact_type"] == "finetuned_model"), 0)
    choice = st.selectbox("Focus artifact", list(options), index=default)
    focus = options[choice]
    st.graphviz_chart(dot(graph, focus), width="stretch")
    st.caption("Colours show the last verification result stored in the index. Re-verify on the "
               "Verify page: the stored status is never trusted by the verifier itself.")

    detail = get(f"/artifacts/{focus}")
    lin = get(f"/artifacts/{focus}/lineage")
    names = {a["artifact_id"]: a["artifact_name"] for a in artifacts}
    c1, c2 = st.columns(2)
    c1.markdown("**Ancestors**  \n" + ("  \n".join(f"- {names.get(i, i)}" for i in lin["ancestors"]) or "none"))
    c2.markdown("**Descendants**  \n" + ("  \n".join(f"- {names.get(i, i)}" for i in lin["descendants"]) or "none"))

    env = detail["envelope"]
    if env:
        p = env["payload"]
        st.subheader("Signed manifest")
        m1, m2, m3 = st.columns(3)
        m1.markdown(f"**Signer**  \n`{p['signer']['identity']}`  \n`{p['signer']['key_id']}`")
        m2.markdown(f"**Subject SHA-256**  \n`{p['subject']['sha256'][:32]}…`  \n{p['subject']['size_bytes']:,} bytes")
        m3.markdown(f"**Manifest digest**  \n`{env['manifest_digest'][:39]}…`")
        if p["subject"].get("merkle"):
            st.markdown(f"**Merkle root** `{p['subject']['merkle']['root']}` over "
                        f"{p['subject']['merkle']['leaf_count']} rows")
        with st.expander("Full envelope (JSON)"):
            st.json(env)
    else:
        st.error("No signed envelope found for this artifact.")
    with st.expander("Mutable index state (not signed)"):
        st.json(detail["index"])

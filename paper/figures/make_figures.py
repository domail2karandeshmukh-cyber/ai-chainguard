"""Regenerate every figure and every quoted number of the IEEE paper from results/.

    python paper/figures/make_figures.py          # writes paper/figures/*.pdf and analysis.json

Inputs (all produced by the repository's own scripts):
    results/attacks/summary.csv, results/attacks/scenario_E.json, scenario_G.json, scenario_F.json
    results/metrics/inference_benchmark.csv, manifest_sizes.csv, trustlog_benchmark.csv, benchmark.csv
    results/pipeline/last_run.json, results/validation_logs/2_pytest.log
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
RES = ROOT / "results"
OUT = Path(__file__).resolve().parent
COL = {"VERIFIED": "#1f9d55", "WARNING": "#d69e2e", "FAILED": "#c53030", "REFUSED": "#6b46c1"}

plt.rcParams.update({"font.size": 7.5, "font.family": "serif", "axes.titlesize": 8, "axes.labelsize": 7.5,
                     "legend.fontsize": 6.8, "xtick.labelsize": 7, "ytick.labelsize": 7, "pdf.fonttype": 42,
                     "axes.spines.top": False, "axes.spines.right": False})


def read_csv(path: Path) -> list[dict]:
    with path.open() as fh:
        return list(csv.DictReader(fh))


def load() -> dict:
    d: dict = {}
    d["summary"] = read_csv(RES / "attacks" / "summary.csv")
    d["E"] = json.loads((RES / "attacks" / "scenario_E.json").read_text())
    d["G"] = json.loads((RES / "attacks" / "scenario_G.json").read_text())
    d["F"] = json.loads((RES / "attacks" / "scenario_F.json").read_text())
    d["bench"] = read_csv(RES / "metrics" / "inference_benchmark.csv")
    d["sizes"] = read_csv(RES / "metrics" / "manifest_sizes.csv")
    d["tl"] = read_csv(RES / "metrics" / "trustlog_benchmark.csv")
    d["crypto"] = read_csv(RES / "metrics" / "benchmark.csv")
    d["pipeline"] = json.loads((RES / "pipeline" / "last_run.json").read_text())
    log = (RES / "validation_logs" / "2_pytest.log").read_text()
    m = re.search(r"(\d+) passed", log)
    d["tests_passed"] = int(m.group(1)) if m else None
    m = re.search(r"in ([\d.]+)s", log)
    d["tests_seconds"] = float(m.group(1)) if m else None
    return d


# --------------------------------------------------------------------------- figure: boundary
def fig_boundary(d: dict, a: dict) -> None:
    ev = {v["variant"]: v for v in d["E"]["variants"]}
    gv = {v["variant"]: v for v in d["G"]["variants"]}
    items = [("E0", "clean\nbaseline", ev["E0"]), ("E2", "poison before\nsigning", ev["E2"]),
             ("E3", "poison +\ncontent checks", ev["E3"]), ("E4", "adaptive\ntrigger", ev["E4"]),
             ("E7-F", "trusted hub,\nbackdoored", gv["E7-F"])]
    fig, ax = plt.subplots(figsize=(3.45, 2.35))
    x = range(len(items))
    acc = [it[2]["details"]["clean_accuracy"] for it in items]
    asr = [it[2]["details"]["attack_success_rate"] for it in items]
    w = 0.36
    ax.bar([i - w / 2 for i in x], acc, w, color="#2b6cb0", label="clean test accuracy")
    ax.bar([i + w / 2 for i in x], asr, w, color="#c53030", label="backdoor success rate (trigger → 7)")
    for i, it in enumerate(items):
        st = it[2]["observed"]
        dep = it[2]["details"].get("deployed")
        label = st + ("\ndeployed" if dep else ("\nblocked" if dep is False else "\nimported"))
        ax.text(i, 1.06, label, ha="center", va="bottom", fontsize=6.2, color=COL[st], fontweight="bold")
        ax.text(i + w / 2, asr[i] - 0.09 if asr[i] > 0.2 else asr[i] + 0.02, f"{asr[i] * 100:.0f}%",
                ha="center", va="bottom", fontsize=6, color="white" if asr[i] > 0.2 else "black")
        ax.text(i - w / 2, acc[i] - 0.09, f"{acc[i] * 100:.0f}%", ha="center", va="bottom", fontsize=6, color="white")
    ax.set_xticks(list(x))
    ax.set_xticklabels([f"{it[0]}\n{it[1]}" for it in items], fontsize=6.3)
    ax.set_ylim(0, 1.33)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_ylabel("rate")
    fig.legend(loc="lower center", ncol=2, frameon=False, bbox_to_anchor=(0.5, -0.01))
    fig.tight_layout(pad=0.3, rect=(0, 0.07, 1, 1))
    fig.savefig(OUT / "fig_boundary.pdf")
    plt.close(fig)
    a["boundary"] = {it[0]: {"status": it[2]["observed"], "clean_accuracy": acc[i], "asr": asr[i],
                             "deployed": it[2]["details"].get("deployed")} for i, it in enumerate(items)}


# --------------------------------------------------------------------------- figure: detection + cost
def fig_detection_cost(d: dict, a: dict) -> None:
    rows = d["summary"]
    order = ["A", "B", "C", "D", "E", "F", "G"]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.1, 2.3), gridspec_kw={"width_ratios": [1.25, 1]})
    # (a) detection time per variant, one row per scenario
    y_pos = {s: i for i, s in enumerate(order)}
    seen: dict[str, int] = {}
    for r in rows:
        k = seen.get(r["scenario"], 0)
        seen[r["scenario"]] = k + 1
        ax1.scatter(float(r["detection_ms"]), y_pos[r["scenario"]] + ((k % 5) - 2) * 0.07,
                    s=14, color=COL[r["observed"]], edgecolor="black", linewidth=0.3, zorder=3)
    ax1.set_yticks(range(len(order)))
    labels = {"A": "A dataset tampering", "B": "B model substitution", "C": "C broken provenance",
              "D": "D invalid signature", "E": "E poison before signing", "F": "F revocation + bypasses",
              "G": "G external source"}
    ax1.set_yticklabels([labels[s] for s in order])
    ax1.invert_yaxis()
    ax1.set_xscale("log")
    ax1.set_xlim(0.5, 40)
    ax1.set_xticks([1, 2, 5, 10, 20])
    ax1.set_xticklabels(["1", "2", "5", "10", "20"])
    ax1.minorticks_off()
    ax1.set_xlabel("verification time of the attacked artifact incl. its chain (ms, log)")
    ax1.grid(axis="x", alpha=0.3)
    for st, c in COL.items():
        ax1.scatter([], [], color=c, s=14, label=st.lower(), edgecolor="black", linewidth=0.3)
    ax1.legend(loc="center left", frameon=False, ncol=1, title=f"{len(rows)} variants, observed status",
               title_fontsize=6.5, bbox_to_anchor=(0.0, 0.42))
    ax1.set_title("(a) attack suite: outcome and detection time", loc="left")

    # (b) cost: inference, verification, deployment, trust-log replay
    b = {r["measurement"] + "|" + r["label"]: r for r in d["bench"]}
    def pick(key: str):
        return next(v for k, v in b.items() if k.startswith(key))
    items = [
        ("A  inference, 1 sample", pick("A|normal inference, 1 sample"), "#2b6cb0"),
        ("D  inference after verified deploy", pick("D|subsequent inference, 1 sample"), "#2b6cb0"),
        ("B  full chain verification V0-V9", pick("B|full chain"), "#2c7a7b"),
        ("C1 verify + audit log + safe read", pick("C|C1"), "#805ad5"),
        ("C2 safe load (safetensors)", pick("C|C2"), "#805ad5"),
        ("C3 smoke test (360 samples)", pick("C|C3"), "#805ad5"),
        ("C  first secure deployment, total", pick("C|first secure"), "#553c9a"),
    ]
    tl = {int(r["records"]): r for r in d["tl"]}
    names = [it[0] for it in items] + [f"trust log replay, {n} records" for n in (5, 50, 500)]
    med = [float(it[1]["median_ms"]) for it in items] + [float(tl[n]["cold_median_ms"]) for n in (5, 50, 500)]
    p95 = [float(it[1]["p95_ms"]) for it in items] + [float(tl[n]["cold_p95_ms"]) for n in (5, 50, 500)]
    colors = [it[2] for it in items] + ["#b7791f"] * 3
    y = range(len(names))
    ax2.barh(list(y), med, color=colors, height=0.62)
    ax2.errorbar(med, list(y), xerr=[[0] * len(med), [p - m for p, m in zip(p95, med, strict=True)]],
                 fmt="none", ecolor="black", elinewidth=0.6, capsize=1.5)
    for i, m in enumerate(med):
        ax2.text(m * 1.25, i, f"{m:.2f}" if m < 10 else f"{m:.0f}", va="center", fontsize=6)
    ax2.set_yticks(list(y))
    ax2.set_yticklabels(names, fontsize=6.3)
    ax2.invert_yaxis()
    ax2.set_xscale("log")
    ax2.set_xlim(0.03, 3000)
    ax2.set_xticks([0.1, 1, 10, 100, 1000])
    ax2.set_xticklabels(["0.1", "1", "10", "100", "1000"])
    ax2.minorticks_off()
    ax2.set_xlabel("time (ms, log scale); bar median, whisker p95")
    ax2.grid(axis="x", alpha=0.3)
    ax2.set_title("(b) what attestation costs", loc="left")
    fig.tight_layout(pad=0.4, w_pad=1.0)
    fig.savefig(OUT / "fig_detection_cost.pdf")
    plt.close(fig)
    a["bench"] = {it[0].strip(): {"median_ms": float(it[1]["median_ms"]), "p95_ms": float(it[1]["p95_ms"]),
                                  "runs": int(it[1]["runs"])} for it in items}
    a["trustlog"] = {n: {k: float(v) if k != "records" else int(v) for k, v in tl[n].items()} for n in tl}


# --------------------------------------------------------------------------- numbers
def numbers(d: dict, a: dict) -> None:
    rows = d["summary"]
    a["variants_total"] = len(rows)
    a["variants_as_expected"] = sum(r["as_expected"] == "True" for r in rows)
    per = {}
    for r in rows:
        s = per.setdefault(r["scenario"], {"n": 0, "ok": 0, "statuses": {}})
        s["n"] += 1
        s["ok"] += r["as_expected"] == "True"
        s["statuses"][r["observed"]] = s["statuses"].get(r["observed"], 0) + 1
    a["per_scenario"] = per
    det = [float(r["detection_ms"]) for r in rows]
    a["detection_ms"] = {"min": min(det), "max": max(det), "median": sorted(det)[len(det) // 2]}
    a["tests_passed"] = d["tests_passed"]
    a["tests_seconds"] = d["tests_seconds"]
    p = d["pipeline"]
    a["pipeline"] = {"clean_accuracy": p["evaluation"]["final"]["clean_accuracy"],
                     "attestation_ms": p["overhead"]["attestation_ms"], "training_ms": p["overhead"]["training_ms"],
                     "attestation_pct": p["overhead"]["attestation_vs_training_pct"],
                     "gateway_verification_ms": p["deployment"].get("verification_ms")}
    sizes = {r["artifact_type"] + "/" + r["artifact_name"]: r for r in d["sizes"]}
    a["manifest_sizes"] = {k: {kk: (int(vv) if vv.isdigit() else vv) for kk, vv in r.items()} for k, r in sizes.items()}
    env = [int(r["envelope_bytes"]) for r in d["sizes"] if r.get("envelope_bytes", "").isdigit()]
    if env:
        a["envelope_bytes_min_max"] = [min(env), max(env)]
    # crypto throughput (SHA-256 at the largest size, Ed25519)
    cr = d["crypto"]
    a["crypto_columns"] = list(cr[0].keys()) if cr else []
    fv = [v for v in d["F"]["variants"]]
    a["F"] = {v["variant"]: {"observed": v["observed"], "failed": v["failed_checks"]} for v in fv}


def main() -> None:
    d = load()
    a: dict = {}
    OUT.mkdir(parents=True, exist_ok=True)
    fig_boundary(d, a)
    fig_detection_cost(d, a)
    numbers(d, a)
    (OUT / "analysis.json").write_text(json.dumps(a, indent=2, default=str) + "\n")
    print(json.dumps({k: a[k] for k in ("variants_total", "variants_as_expected", "tests_passed", "pipeline")}, indent=1))
    print("figures written to", OUT)


if __name__ == "__main__":
    sys.exit(main())

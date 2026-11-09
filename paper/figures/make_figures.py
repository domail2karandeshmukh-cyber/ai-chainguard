"""Regenerate every figure and every quoted number of the IEEE paper from results/.

    python paper/figures/make_figures.py          # writes paper/figures/*.pdf (English and _fr French variants) and analysis.json

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

# Labels of the two figures in both languages of the paper (signed_is_not_safe.tex / signed_is_not_safe_fr.tex).
T = {
    "en": {
        "suffix": "", "rate": "rate (%)", "acc": "clean test accuracy", "asr": "backdoor success rate (trigger \u2192 7)",
        "deployed": "deployed", "blocked": "blocked", "imported": "imported",
        "status": {"VERIFIED": "VERIFIED", "WARNING": "WARNING", "FAILED": "FAILED", "REFUSED": "REFUSED"},
        "items": [("E0", "clean\nbaseline"), ("E2", "poison before\nsigning"), ("E3", "poison +\ncontent checks"),
                  ("E4", "adaptive\ntrigger"), ("E7-F", "trusted\npublisher,\nbackdoored")],
        "scen": {"A": "A dataset tampering", "B": "B model substitution", "C": "C broken provenance",
                 "D": "D invalid signature", "E": "E poison before signing", "F": "F revocation + bypasses",
                 "G": "G external source"},
        "xlab_a": "verification time of the attacked artifact incl. its chain (ms, log)",
        "title_a": "(a) {n} variants: outcome and detection time",
        "bench": ["inference, 1 sample", "inference after verified deploy", "full chain verification V0\u2013V9",
                  "verify + audit log + safe read", "safe load (safetensors)", "smoke test (360 samples)",
                  "first secure deployment, total"],
        "replay": "trust log replay, {n} records", "xlab_b": "time (ms, log scale)",
        "title_b": "(b) what attestation costs",
    },
    "fr": {
        "suffix": "_fr", "rate": "taux (%)", "acc": "exactitude sur donn\u00e9es propres",
        "asr": "taux de succ\u00e8s de la porte d\u00e9rob\u00e9e (d\u00e9clencheur \u2192 7)",
        "deployed": "d\u00e9ploy\u00e9", "blocked": "bloqu\u00e9", "imported": "import\u00e9",
        "status": {"VERIFIED": "V\u00c9RIFI\u00c9", "WARNING": "AVERTISSEMENT", "FAILED": "\u00c9CHEC", "REFUSED": "REFUS\u00c9"},
        "items": [("E0", "r\u00e9f\u00e9rence\npropre"), ("E2", "poison avant\nsignature"), ("E3", "poison +\ncontr\u00f4les"),
                  ("E4", "d\u00e9clencheur\nadaptatif"), ("E7-F", "\u00e9diteur de\nconfiance,\nporte d\u00e9rob\u00e9e")],
        "scen": {"A": "A alt\u00e9ration du jeu de donn\u00e9es", "B": "B substitution du mod\u00e8le",
                 "C": "C provenance bris\u00e9e", "D": "D signature invalide", "E": "E poison avant signature",
                 "F": "F r\u00e9vocation + contournements", "G": "G source externe"},
        "xlab_a": "temps de v\u00e9rification de l'artefact attaqu\u00e9, cha\u00eene comprise (ms, log)",
        "title_a": "(a) {n} variantes : verdict et temps de d\u00e9tection",
        "bench": ["inf\u00e9rence, 1 \u00e9chantillon", "inf\u00e9rence apr\u00e8s d\u00e9ploiement v\u00e9rifi\u00e9",
                  "v\u00e9rification de la cha\u00eene, V0\u2013V9", "v\u00e9rif. + journal d'audit + lecture s\u00fbre",
                  "chargement s\u00fbr (safetensors)", "test de fum\u00e9e (360 \u00e9chantillons)",
                  "premier d\u00e9ploiement s\u00e9curis\u00e9, total"],
        "replay": "rejeu du journal, {n} enregistrements", "xlab_b": "temps (ms, \u00e9chelle log)",
        "title_b": "(b) co\u00fbt de l'attestation",
    },
}


def num(v: float, lang: str, nd: int = 2) -> str:
    """Fixed decimals; decimal comma in French."""
    t = f"{v:.{nd}f}"
    return t.replace(".", ",") if lang == "fr" else t

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
def fig_boundary(d: dict, a: dict, lang: str = "en") -> None:
    t = T[lang]
    ev = {v["variant"]: v for v in d["E"]["variants"]}
    gv = {v["variant"]: v for v in d["G"]["variants"]}
    src = {"E0": ev["E0"], "E2": ev["E2"], "E3": ev["E3"], "E4": ev["E4"], "E7-F": gv["E7-F"]}
    items = [(k, lab, src[k]) for k, lab in t["items"]]
    fig, ax = plt.subplots(figsize=(3.45, 2.2) if lang == "en" else (3.45, 2.0))
    x = range(len(items))
    acc = [it[2]["details"]["clean_accuracy"] for it in items]
    asr = [it[2]["details"]["attack_success_rate"] for it in items]
    w = 0.36
    acc_pct = [v * 100 for v in acc]
    asr_pct = [v * 100 for v in asr]
    ax.bar([i - w / 2 for i in x], acc_pct, w, color="#2b6cb0", label=t["acc"])
    ax.bar([i + w / 2 for i in x], asr_pct, w, color="#c53030", label=t["asr"])
    for i, it in enumerate(items):
        st = it[2]["observed"]
        dep = it[2]["details"].get("deployed")
        label = t["status"][st] + "\n" + (t["deployed"] if dep else (t["blocked"] if dep is False else t["imported"]))
        ax.text(i, 106, label, ha="center", va="bottom", fontsize=6.2 if lang == "en" else 5.1, color=COL[st],
                fontweight="bold")
        # value labels: inside the bar (white) when the bar is tall enough, above it otherwise; no unit, the axis has it
        inside = asr_pct[i] > 20
        ax.text(i + w / 2, asr_pct[i] - 9 if inside else asr_pct[i] + 2, f"{asr_pct[i]:.0f}", ha="center", va="bottom",
                fontsize=5.6, color="white" if inside else "black")
        ax.text(i - w / 2, acc_pct[i] - 9, f"{acc_pct[i]:.0f}", ha="center", va="bottom", fontsize=5.6, color="white")
    ax.set_xticks(list(x))
    ax.set_xticklabels([f"{it[0]}\n{it[1]}" for it in items], fontsize=6.3 if lang == "en" else 5.6)
    ax.set_ylim(0, 133)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_ylabel(t["rate"])
    if lang == "en":
        fig.legend(loc="lower center", ncol=2, frameon=False, bbox_to_anchor=(0.5, -0.01), fontsize=6.8)
        fig.tight_layout(pad=0.3, rect=(0, 0.07, 1, 1))
    else:
        fig.legend(loc="lower center", ncol=1, frameon=False, bbox_to_anchor=(0.5, -0.01), fontsize=6.0,
                   handlelength=1.2, labelspacing=0.15)
        fig.tight_layout(pad=0.3, rect=(0, 0.13, 1, 1))
    fig.savefig(OUT / f"fig_boundary{t['suffix']}.pdf")
    plt.close(fig)
    a["boundary"] = {it[0]: {"status": it[2]["observed"], "clean_accuracy": acc[i], "asr": asr[i],
                             "deployed": it[2]["details"].get("deployed")} for i, it in enumerate(items)}


# --------------------------------------------------------------------------- figure: detection + cost
def fig_detection_cost(d: dict, a: dict, lang: str = "en") -> None:
    t = T[lang]
    rows = d["summary"]
    order = ["A", "B", "C", "D", "E", "F", "G"]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.1, 2.05) if lang == "en" else (7.1, 1.85),
                                   gridspec_kw={"width_ratios": [1.25, 1]})
    # (a) detection time per variant, one row per scenario
    y_pos = {s: i for i, s in enumerate(order)}
    seen: dict[str, int] = {}
    for r in rows:
        k = seen.get(r["scenario"], 0)
        seen[r["scenario"]] = k + 1
        ax1.scatter(float(r["detection_ms"]), y_pos[r["scenario"]] + ((k % 5) - 2) * 0.07,
                    s=14, color=COL[r["observed"]], edgecolor="black", linewidth=0.3, zorder=3)
    ax1.set_yticks(range(len(order)))
    labels = t["scen"]
    ax1.set_yticklabels([labels[s] for s in order], fontsize=7 if lang == "en" else 6.4)
    ax1.invert_yaxis()
    ax1.set_xscale("log")
    ax1.set_xlim(0.8, 40)
    ax1.set_xticks([1, 2, 5, 10, 20])
    ax1.set_xticklabels(["1", "2", "5", "10", "20"])
    ax1.minorticks_off()
    ax1.set_xlabel(t["xlab_a"])
    ax1.grid(axis="x", alpha=0.3)
    for st, c in COL.items():
        ax1.scatter([], [], color=c, s=14, label=t["status"][st].lower(), edgecolor="black", linewidth=0.3)
    ax1.legend(loc="lower right", frameon=False, ncol=4, bbox_to_anchor=(1.0, 1.0), borderaxespad=0.0,
               handletextpad=0.2, columnspacing=0.7, fontsize=6.3)
    ax1.set_title(t["title_a"].format(n=len(rows)), loc="left", pad=14)

    # (b) cost: inference, verification, deployment, trust-log replay
    b = {r["measurement"] + "|" + r["label"]: r for r in d["bench"]}
    def pick(key: str):
        return next(v for k, v in b.items() if k.startswith(key))
    keys = ["A|normal inference, 1 sample", "D|subsequent inference, 1 sample", "B|full chain", "C|C1", "C|C2", "C|C3",
            "C|first secure"]
    cols = ["#2b6cb0", "#2b6cb0", "#2c7a7b", "#805ad5", "#805ad5", "#805ad5", "#553c9a"]
    items = [(lab, pick(k), c) for lab, k, c in zip(t["bench"], keys, cols, strict=True)]
    tl = {int(r["records"]): r for r in d["tl"]}
    names = [it[0] for it in items] + [t["replay"].format(n=n) for n in (5, 50, 500)]
    med = [float(it[1]["median_ms"]) for it in items] + [float(tl[n]["cold_median_ms"]) for n in (5, 50, 500)]
    p95 = [float(it[1]["p95_ms"]) for it in items] + [float(tl[n]["cold_p95_ms"]) for n in (5, 50, 500)]
    colors = [it[2] for it in items] + ["#b7791f"] * 3
    y = range(len(names))
    ax2.barh(list(y), med, color=colors, height=0.62)
    ax2.errorbar(med, list(y), xerr=[[0] * len(med), [p - m for p, m in zip(p95, med, strict=True)]],
                 fmt="none", ecolor="black", elinewidth=0.6, capsize=1.5)
    for i, (m, p) in enumerate(zip(med, p95, strict=True)):
        nd = 3 if m < 1 else (2 if m < 10 else (1 if m < 100 else 0))
        ax2.text(max(m, p) * 1.18, i, num(m, lang, nd), va="center", fontsize=6)
    ax2.set_yticks(list(y))
    ax2.set_yticklabels(names, fontsize=6.3 if lang == "en" else 5.7)
    ax2.invert_yaxis()
    ax2.set_xscale("log")
    ax2.set_xlim(0.03, 4000)
    ax2.set_xticks([0.1, 1, 10, 100, 1000])
    ax2.set_xticklabels(["0,1" if lang == "fr" else "0.1", "1", "10", "100", "1000"])
    ax2.minorticks_off()
    ax2.set_xlabel(t["xlab_b"])
    ax2.grid(axis="x", alpha=0.3)
    ax2.set_title(t["title_b"], loc="left")
    fig.tight_layout(pad=0.4, w_pad=1.0)
    fig.savefig(OUT / f"fig_detection_cost{t['suffix']}.pdf")
    plt.close(fig)
    a["bench"] = {en.strip(): {"median_ms": float(it[1]["median_ms"]), "p95_ms": float(it[1]["p95_ms"]),
                              "runs": int(it[1]["runs"])} for en, it in zip(T["en"]["bench"], items, strict=True)}
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
    # crypto micro-benchmarks quoted in Section V: SHA-256 at the largest size, Ed25519 sign/verify, Merkle over rows
    cr = d["crypto"]
    a["crypto_columns"] = list(cr[0].keys()) if cr else []
    if cr:
        largest = max(cr, key=lambda r: int(r["size_bytes"]))
        a["crypto"] = {"sha256_largest_label": largest["size_label"], "sha256_largest_ms": float(largest["sha256_ms"]),
                       "sha256_GBps_at_largest": round(int(largest["size_bytes"]) / float(largest["sha256_ms"]) / 1e6, 3),
                       "ed25519_sign_ms_min_max": [min(float(r["sign_ms"]) for r in cr), max(float(r["sign_ms"]) for r in cr)],
                       "ed25519_verify_ms_min_max": [min(float(r["verify_sig_ms"]) for r in cr),
                                                     max(float(r["verify_sig_ms"]) for r in cr)]}
    mk = read_csv(RES / "metrics" / "benchmark_merkle.csv")
    a["merkle_rows_ms"] = {int(r["rows"]): float(r["merkle_ms"]) for r in mk}
    fv = [v for v in d["F"]["variants"]]
    a["F"] = {v["variant"]: {"observed": v["observed"], "failed": v["failed_checks"]} for v in fv}


def main() -> None:
    d = load()
    a: dict = {}
    OUT.mkdir(parents=True, exist_ok=True)
    for lang in ("en", "fr"):
        fig_boundary(d, a, lang)
        fig_detection_cost(d, a, lang)
    numbers(d, a)
    (OUT / "analysis.json").write_text(json.dumps(a, indent=2, default=str) + "\n")
    print(json.dumps({k: a[k] for k in ("variants_total", "variants_as_expected", "tests_passed", "pipeline")}, indent=1))
    print("figures written to", OUT)


if __name__ == "__main__":
    sys.exit(main())

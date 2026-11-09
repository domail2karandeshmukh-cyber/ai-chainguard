"""Turn experiment results into report figures (PNG, 200 dpi) and tables (CSV/Markdown).

Inputs (whatever exists is used):
    results/metrics/benchmark.csv, results/metrics/benchmark_merkle.csv  (scripts.benchmark)
    results/attacks/scenario_*.json                                      (attacks.run_all)
    results/pipeline/last_run.json                                       (ml_pipeline.run_pipeline)
    results/metrics/inference_benchmark.json                             (scripts.benchmark, v0.3)
Outputs:
    results/figures/*.png and results/figures/attack_table.md

    python -m scripts.make_figures
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path

import matplotlib
import matplotlib.ticker

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from chainguard.config import REPO_ROOT  # noqa: E402

INK, MUTED, GRID = "#1f2937", "#6b7280", "#e5e7eb"
BLUE, GREEN, AMBER, RED = "#2563eb", "#16a34a", "#d97706", "#dc2626"
PURPLE = "#7c3aed"
STATUS_COLOR = {"VERIFIED": GREEN, "WARNING": AMBER, "FAILED": RED, "REFUSED": PURPLE}

plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK,
    "axes.grid": True, "grid.color": GRID, "axes.axisbelow": True, "axes.spines.top": False,
    "axes.spines.right": False, "figure.dpi": 110, "savefig.bbox": "tight",
})


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open() as fh:
        return list(csv.DictReader(fh))


def fig_hash_vs_size(rows, out: Path) -> None:
    size_mb = [int(r["size_bytes"]) / 2**20 for r in rows]
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    ax.loglog(size_mb, [float(r["sha256_ms"]) for r in rows], "o-", color=BLUE, label="SHA-256 (streamed)")
    ax.loglog(size_mb, [float(r["verify_full_ms"]) for r in rows], "s-", color=GREEN, label="full verification V0-V9")
    ax.loglog(size_mb, [float(r["sign_ms"]) for r in rows], "^-", color=AMBER, label="Ed25519 sign (manifest)")
    ax.loglog(size_mb, [float(r["verify_sig_ms"]) for r in rows], "v-", color=RED, label="Ed25519 verify")
    ax.set_xlabel("artifact size (MiB)")
    ax.set_ylabel("median time (ms)")
    ax.set_title("Hashing grows linearly with size; signatures stay constant", loc="left", fontsize=11)
    ax.legend(frameon=False, fontsize=9)
    fig.savefig(out / "fig_cost_vs_size.png", dpi=200)
    plt.close(fig)


def fig_merkle(rows, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(5.6, 3.4))
    n = [int(r["rows"]) for r in rows]
    ax.loglog(n, [float(r["merkle_ms"]) for r in rows], "o-", color=BLUE)
    for x, r in zip(n, rows, strict=True):
        ax.annotate(f"{float(r['merkle_ms']):.0f} ms", (x, float(r["merkle_ms"])), textcoords="offset points",
                    xytext=(4, -12), fontsize=8, color=MUTED)
    ax.set_xlabel("dataset rows (leaves)")
    ax.set_ylabel("Merkle root time (ms)")
    ax.set_title("Row-level Merkle tree cost is linear in rows", loc="left", fontsize=11)
    fig.savefig(out / "fig_merkle_rows.png", dpi=200)
    plt.close(fig)


def fig_attacks(results, out: Path) -> None:
    variants = [(r["scenario"], v) for r in results for v in r["variants"]]
    fig, ax = plt.subplots(figsize=(7.6, 0.32 * len(variants) + 1.0))
    labels, colors, widths = [], [], []
    for _, v in variants:
        labels.append(f"{v['variant']}  {v['title']}")
        colors.append(STATUS_COLOR.get(v["observed"], MUTED))
        widths.append(max(v["detection_ms"], 0.05))
    y = list(range(len(variants)))[::-1]
    ax.barh(y, widths, color=colors, height=0.65)
    ax.set_yticks(y, labels, fontsize=8)
    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}"))
    ax.xaxis.set_minor_formatter(matplotlib.ticker.NullFormatter())
    ax.set_xlabel("verification time of the attacked artifact, incl. its whole chain (ms, log)")
    for yi, (_, v), w in zip(y, variants, widths, strict=True):
        mark = "" if v["as_expected"] else "  UNEXPECTED"
        checks = ",".join(v["failed_checks"] or v["warned_checks"])
        ax.text(w * 1.15, yi, f"{v['observed']} {checks}{mark}", va="center", fontsize=7.5, color=INK)
    ax.set_xlim(right=max(widths) * 6)
    ax.set_title("Attack scenarios: observed status and detection time", loc="left", fontsize=11)
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in STATUS_COLOR.values()]
    ax.legend(handles, list(STATUS_COLOR), frameon=False, fontsize=8, loc="lower right")
    fig.savefig(out / "fig_attack_outcomes.png", dpi=200)
    plt.close(fig)


def fig_backdoor(result_e, out: Path) -> None:
    rows = [v for v in result_e["variants"] if "attack_success_rate" in v["details"]]
    fig, ax = plt.subplots(figsize=(6.6, 3.6))
    x = range(len(rows))
    acc = [v["details"]["clean_accuracy"] for v in rows]
    asr = [v["details"]["attack_success_rate"] for v in rows]
    ax.bar([i - 0.2 for i in x], acc, width=0.38, color=BLUE, label="clean test accuracy")
    ax.bar([i + 0.2 for i in x], asr, width=0.38, color=RED, label="attack success rate (trigger -> 7)")
    for i, v in enumerate(rows):
        dep = "deployed" if v["details"]["deployed"] else "blocked"
        ax.text(i, 1.04, f"{v['observed']}\n{dep}", ha="center", fontsize=8,
                color=STATUS_COLOR.get(v["observed"], INK), fontweight="bold")
    short = {"E0": "clean baseline", "E2": "poison before signing\nno content checks",
             "E3": "poison before signing\ncontent checks on", "E4": "adaptive trigger\ncontent checks on"}
    ax.set_xticks(list(x), [f"{v['variant']}\n{short.get(v['variant'], v['title'])}" for v in rows], fontsize=8)
    ax.set_ylim(0, 1.22)
    ax.set_ylabel("rate")
    ax.legend(frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.24), ncol=2)
    ax.set_title("Signed poison verifies: backdoored models pass attestation", loc="left", fontsize=11)
    fig.savefig(out / "fig_backdoor_asr.png", dpi=200)
    plt.close(fig)


def fig_overhead(run, out: Path) -> None:
    o = run["overhead"]
    verify_ms = run.get("deployment", {}).get("verification_ms") or 0
    labels = ["training (base + fine-tune)", "attestation (4 artifacts)", "gateway chain verification"]
    vals = [o["training_ms"], o["attestation_ms"], verify_ms]
    fig, ax = plt.subplots(figsize=(6.4, 2.6))
    ax.barh(labels[::-1], vals[::-1], color=[GREEN, AMBER, BLUE][::-1])
    for i, v in enumerate(vals[::-1]):
        ax.text(v * 1.02, i, f"{v:,.1f} ms", va="center", fontsize=8)
    ax.set_xlim(right=max(vals) * 1.25)
    ax.set_xlabel("ms")
    ax.set_title(f"Attestation costs {o['attestation_vs_training_pct']:.2f}% of training time", loc="left",
                 fontsize=11)
    fig.savefig(out / "fig_overhead.png", dpi=200)
    plt.close(fig)


def fig_inference(bench, out: Path) -> None:
    """Median per measurement (bar) with its p95 (whisker), one log axis (v0.3)."""
    group_color = {"A": BLUE, "D": BLUE, "B": AMBER, "C": PURPLE}
    group_name = {"A": "A normal inference", "B": "B verification", "C": "C first secure deployment",
                  "D": "D inference after verified deployment"}
    rows = sorted(bench["rows"], key=lambda r: "ADBC".index(r["measurement"]))
    fig, ax = plt.subplots(figsize=(7.6, 0.42 * len(rows) + 1.4))
    y = list(range(len(rows)))[::-1]
    med = [r["median_ms"] for r in rows]
    p95 = [r["p95_ms"] for r in rows]
    ax.barh(y, med, color=[group_color[r["measurement"]] for r in rows], height=0.62)
    ax.errorbar(med, y, xerr=[[0] * len(rows), [max(p - m, 0) for p, m in zip(p95, med, strict=True)]],
                fmt="none", ecolor=INK, elinewidth=1, capsize=3)
    ax.set_yticks(y, [f"{r['measurement']}  {r['label']}" for r in rows], fontsize=8)
    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}"))
    ax.xaxis.set_minor_formatter(matplotlib.ticker.NullFormatter())
    for yi, r in zip(y, rows, strict=True):
        ax.text(r["p95_ms"] * 1.25, yi, f"median {r['median_ms']:.3g} ms · p95 {r['p95_ms']:.3g} · n={r['runs']}",
                va="center", fontsize=7.5, color=INK)
    ax.set_xlim(right=max(p95) * 40)
    ax.set_xlabel("time (ms, log scale) - bar = median, whisker = p95")
    m = bench["machine"]
    ax.set_title("Chain verification runs once at deployment; predictions pay no verification cost",
                 loc="left", fontsize=10.5)
    fig.text(0.01, -0.08, f"{m['machine_label']} | {m['cpu']}, {m['logical_cpus']} logical CPUs, torch "
             f"{m['torch']}, {m['torch_threads']} threads | model {bench['model']['file_bytes']:,} B, "
             f"{bench['model']['parameters']:,} params", fontsize=6.5, color=MUTED)
    handles = [plt.Rectangle((0, 0), 1, 1, color=group_color[g]) for g in ("A", "B", "C")]
    ax.legend(handles, ["inference (A, D)", group_name["B"], group_name["C"]], frameon=False, fontsize=8,
              loc="upper center", bbox_to_anchor=(0.45, -0.16), ncol=3)
    fig.savefig(out / "fig_inference_overhead.png", dpi=200)
    plt.close(fig)


def attack_table(results, out: Path) -> None:
    lines = ["| Scenario | Variant | Attack | Expected | Observed | Checks | Detection (ms) |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in results:
        for v in r["variants"]:
            lines.append(f"| {r['scenario']} | {v['variant']} | {v['title']} | {v['expected']} | {v['observed']} | "
                         f"{', '.join(v['failed_checks'] or v['warned_checks']) or '-'} | {v['detection_ms']:.2f} |")
    (out / "attack_table.md").write_text("\n".join(lines) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(Path(os.environ.get("CHAINGUARD_HOME") or REPO_ROOT) / "results"))
    args = ap.parse_args()
    res = Path(args.results)
    out = res / "figures"
    out.mkdir(parents=True, exist_ok=True)
    made = []
    if (res / "metrics" / "benchmark.csv").exists():
        fig_hash_vs_size(read_csv(res / "metrics" / "benchmark.csv"), out)
        made.append("fig_cost_vs_size.png")
    if (res / "metrics" / "benchmark_merkle.csv").exists():
        fig_merkle(read_csv(res / "metrics" / "benchmark_merkle.csv"), out)
        made.append("fig_merkle_rows.png")
    results = [json.loads(p.read_text()) for p in sorted((res / "attacks").glob("scenario_*.json"))]
    if results:
        fig_attacks(results, out)
        attack_table(results, out)
        made += ["fig_attack_outcomes.png", "attack_table.md"]
        e = next((r for r in results if r["scenario"] == "E"), None)
        if e:
            fig_backdoor(e, out)
            made.append("fig_backdoor_asr.png")
    bench_file = res / "metrics" / "inference_benchmark.json"
    if bench_file.exists():
        fig_inference(json.loads(bench_file.read_text()), out)
        made.append("fig_inference_overhead.png")
    run_file = res / "pipeline" / "last_run.json"
    if run_file.exists():
        fig_overhead(json.loads(run_file.read_text()), out)
        made.append("fig_overhead.png")
    print("created:", ", ".join(made) or "nothing (run the benchmark, attacks and pipeline first)")


if __name__ == "__main__":
    main()

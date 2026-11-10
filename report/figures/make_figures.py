"""Draw the charts of the final report from results/ (vector PDF, fonts embedded).

    python report/figures/make_figures.py

Inputs, all produced by the repository's own scripts:
    results/attacks/summary.csv, scenario_E.json, scenario_G.json, e2_finetune_poison.json, seed_robustness.json
    results/metrics/inference_benchmark.csv, benchmark.csv, benchmark_merkle.csv, trustlog_benchmark.csv
    results/pipeline/last_run.json
Outputs: report/figures/fig_outcomes.pdf, fig_boundary.pdf, fig_cost.pdf, fig_scaling.pdf, fig_seeds.pdf
and report/figures/numbers.json (every value drawn, for the consistency check of the report).
"""

from __future__ import annotations

import csv
import json
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RES = ROOT / "results"

for ttf in sorted((HERE.parent / "fonts").glob("IBMPlexSans-*.ttf")):
    font_manager.fontManager.addfont(str(ttf))

NAVY, INK, MUTED, RULE, BAND = "#0F2A44", "#1C2633", "#5A6676", "#CFD8D3", "#EEF2EF"
TEAL, SOFT = "#0E7C86", "#A9BACB"
# Status colours. The chart amber is lighter than the text amber of the report so that a WARNING mark
# stays distinct from a FAILED mark for colour-blind readers (checked with a CVD simulation, all pairs).
COL = {"VERIFIED": TEAL, "FAILED": "#B42318", "WARNING": "#B8860B", "REFUSED": "#6B46C1"}
CHIP = {"VERIFIED": TEAL, "FAILED": "#B42318", "WARNING": "#875900", "REFUSED": "#6B46C1"}
W = 5.9  # text width of the report in inches (15 cm)

plt.rcParams.update({
    "font.family": "IBM Plex Sans", "font.size": 8, "axes.labelsize": 8, "axes.titlesize": 8.5,
    "xtick.labelsize": 7.5, "ytick.labelsize": 7.5, "legend.fontsize": 7.5, "pdf.fonttype": 42,
    "axes.spines.top": False, "axes.spines.right": False, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
    "xtick.color": MUTED, "ytick.color": MUTED, "text.color": INK, "axes.linewidth": 0.6,
    "xtick.major.width": 0.6, "ytick.major.width": 0.6, "hatch.linewidth": 0.6,
})
NUM: dict = {}


def rows(path: Path) -> list[dict]:
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def save(fig, name: str) -> None:
    fig.savefig(HERE / name, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)
    print(name)


# ---------------------------------------------------------------------------------------------------
# Figure: the 48 variants, one tile each, and the verification time of each experiment
# ---------------------------------------------------------------------------------------------------
EXPERIMENTS = [
    ("A", "1  Dataset tampering"), ("B", "2  Model substitution"), ("D", "3  Invalid signature, key misuse"),
    ("C", "4  Broken provenance"), ("F", "5  Revocation and its bypasses"), ("E", "6  Poison before signing"),
    ("G", "7  Untrusted external source"),
]


def fig_outcomes() -> None:
    summary = rows(RES / "attacks" / "summary.csv")
    fig = plt.figure(figsize=(W, 2.95))
    gs = fig.add_gridspec(1, 2, width_ratios=[3.05, 1.0], wspace=0.05, left=0.285, right=0.995, top=0.875, bottom=0.14)
    ax, bx = fig.add_subplot(gs[0]), fig.add_subplot(gs[1])
    n_rows = len(EXPERIMENTS)
    NUM["outcomes"] = {}
    for i, (sc, _label) in enumerate(EXPERIMENTS):
        y = n_rows - 1 - i
        vs = [r for r in summary if r["scenario"] == sc]
        ok = sum(r["as_expected"] == "True" for r in vs)
        times = [float(r["detection_ms"]) for r in vs]
        for j, r in enumerate(vs):
            st = r["observed"]
            ax.add_patch(FancyBboxPatch((j + 0.07, y - 0.36), 0.86, 0.72, boxstyle="round,pad=0,rounding_size=0.14",
                                        fc=COL[st], ec="none", hatch="////" if st == "REFUSED" else None,
                                        zorder=2))
            if st == "REFUSED":  # hatch is drawn in the edge colour
                ax.patches[-1].set_edgecolor("#FFFFFF55")
                ax.patches[-1].set_linewidth(0)
            tag = r["variant"].replace("E5-", "").replace("E7-", "")
            ax.text(j + 0.5, y - 0.01, tag, ha="center", va="center", fontsize=6.4, fontweight="semibold",
                    color=NAVY if st == "WARNING" else "white", zorder=3)
        ax.text(len(vs) + 0.25, y, f"{ok}/{len(vs)}", ha="left", va="center", fontsize=7.5, color=MUTED)
        bx.plot([min(times), max(times)], [y, y], color=SOFT, lw=2.6, solid_capstyle="round", zorder=1)
        bx.plot(statistics.median(times), y, "o", ms=4.6, color=NAVY, mec="white", mew=0.8, zorder=3)
        NUM["outcomes"][sc] = {"n": len(vs), "as_expected": ok, "min_ms": min(times), "max_ms": max(times),
                               "median_ms": round(statistics.median(times), 3)}
    ax.set_xlim(0, 14.4)
    ax.set_ylim(-0.6, n_rows - 0.4)
    ax.set_yticks(range(n_rows))
    ax.set_yticklabels([lab for _, lab in reversed(EXPERIMENTS)], color=INK, fontsize=8, ha="left")
    ax.tick_params(axis="y", length=0, pad=118)
    ax.set_xticks([])
    for s in ("left", "bottom"):
        ax.spines[s].set_visible(False)
    bx.set_ylim(ax.get_ylim())
    bx.set_yticks([])
    bx.set_xlim(0, 16)
    bx.set_xticks([0, 5, 10, 15])
    bx.set_xlabel("verification time (ms)")
    bx.spines["left"].set_visible(False)
    bx.grid(axis="x", color=RULE, lw=0.5)
    bx.set_axisbelow(True)
    handles = [plt.Rectangle((0, 0), 1, 1, fc=COL[s], ec="#FFFFFF55" if s == "REFUSED" else "none", lw=0,
                             hatch="////" if s == "REFUSED" else None) for s in COL]
    fig.legend(handles, ["VERIFIED", "FAILED", "WARNING", "REFUSED at import"], loc="upper left",
               bbox_to_anchor=(0.0, 1.0), ncol=4, frameon=False, handlelength=1.1, handleheight=1.0,
               columnspacing=1.4, handletextpad=0.5, borderaxespad=0.0, borderpad=0.2)
    fig.text(0.995, 0.955, "range and median", ha="right", va="center", fontsize=7.5, color=MUTED)
    all_t = [float(r["detection_ms"]) for r in summary]
    NUM["outcomes"]["all"] = {"n": len(summary), "as_expected": sum(r["as_expected"] == "True" for r in summary),
                              "min_ms": min(all_t), "max_ms": max(all_t), "median_ms": round(statistics.median(all_t), 3)}
    save(fig, "fig_outcomes.pdf")


# ---------------------------------------------------------------------------------------------------
# Figure: the boundary. Clean accuracy and backdoor success rate, with the verification status
# ---------------------------------------------------------------------------------------------------
def fig_boundary() -> None:
    e = {v["variant"]: v for v in json.loads((RES / "attacks" / "scenario_E.json").read_text())["variants"]}
    g = {v["variant"]: v for v in json.loads((RES / "attacks" / "scenario_G.json").read_text())["variants"]}
    ft = {v["variant"]: v for v in json.loads((RES / "attacks" / "e2_finetune_poison.json").read_text())["variants"]}
    items = []
    for vid, what in (("E0", "clean\nbaseline"), ("E2", "poison before\nsigning"), ("E3", "same poison,\ncontent checks"),
                      ("E4", "adaptive\ntrigger")):
        d = e[vid]["details"]
        items.append((vid, what, e[vid]["observed"], d["clean_accuracy"], d["attack_success_rate"],
                      "deployed" if d["deployed"] else "blocked"))
    d = g["E7-F"]["details"]
    items.append(("E7-F", "trusted publisher,\nbackdoored model", g["E7-F"]["observed"], d["clean_accuracy"],
                  d["attack_success_rate"], "imported"))
    for vid, what in (("FT-E2", "poison in the\nfine-tuning set"), ("FT-E3", "same poison,\ncontent checks")):
        d = ft[vid]
        items.append((vid, what, d["status"], d["clean_accuracy"], d["attack_success_rate"],
                      "deployed" if d["deployed"] else "blocked"))
    xs = [0, 1, 2, 3, 4, 5.45, 6.45]
    fig, ax = plt.subplots(figsize=(W, 3.2))
    fig.subplots_adjust(left=0.075, right=0.995, top=0.91, bottom=0.41)
    bw = 0.36
    NUM["boundary"] = {}
    for x, (vid, what, st, acc, asr, fate) in zip(xs, items, strict=True):
        ax.bar(x - bw / 2 - 0.02, acc * 100, bw, color=SOFT, zorder=2)
        ax.bar(x + bw / 2 + 0.02, asr * 100, bw, color=NAVY, zorder=2)
        ax.text(x - bw / 2 - 0.02, acc * 100 + 1.5, f"{acc * 100:.1f}", ha="center", va="bottom", fontsize=7.2, color=MUTED)
        ax.text(x + bw / 2 + 0.02, asr * 100 + 1.5, f"{asr * 100:.1f}" if asr else "0", ha="center", va="bottom",
                fontsize=7.6, color=INK, fontweight="semibold")
        ax.text(x, -9, vid, ha="center", va="top", fontsize=8.2, fontweight="semibold", color=INK)
        ax.text(x, -20, what, ha="center", va="top", fontsize=7.2, color=MUTED, linespacing=1.15)
        ax.text(x, -49, st, ha="center", va="center", fontsize=6.6, fontweight="semibold", color="white",
                bbox={"boxstyle": "round,pad=0.32,rounding_size=0.5", "fc": CHIP[st], "ec": "none"})
        ax.text(x, -61, fate, ha="center", va="center", fontsize=7.2, color=INK)
        NUM["boundary"][vid] = {"status": st, "clean_accuracy_pct": round(acc * 100, 1), "asr_pct": round(asr * 100, 1),
                                "fate": fate}
    ax.set_ylim(0, 112)
    ax.set_xlim(-0.6, 7.05)
    ax.set_xticks([])
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_ylabel("rate (%)")
    ax.grid(axis="y", color=RULE, lw=0.5)
    ax.set_axisbelow(True)
    ax.spines["bottom"].set_color(RULE)
    ax.axvline(4.72, ymin=-0.62, ymax=1.0, color=RULE, lw=0.8, clip_on=False)
    ax.text(2.0, 113, "reference run, 9 November 2026 (seed 42)", ha="center", va="bottom", fontsize=7.4, color=MUTED)
    ax.text(5.95, 113, "supplementary run, 10 November", ha="center", va="bottom", fontsize=7.4, color=MUTED)
    handles = [plt.Rectangle((0, 0), 1, 1, fc=SOFT), plt.Rectangle((0, 0), 1, 1, fc=NAVY)]
    ax.legend(handles, ["clean test accuracy", "backdoor success rate (trigger read as 7)"], loc="upper center",
              bbox_to_anchor=(0.5, -0.665), ncol=2, frameon=False, handlelength=1.1, handleheight=0.9, columnspacing=2.0)
    save(fig, "fig_boundary.pdf")


# ---------------------------------------------------------------------------------------------------
# Figure: what attestation costs (medians, p95 whiskers), log scale
# ---------------------------------------------------------------------------------------------------
def fig_cost() -> None:
    b = {r["label"]: r for r in rows(RES / "metrics" / "inference_benchmark.csv")}
    tl = {r["records"]: r for r in rows(RES / "metrics" / "trustlog_benchmark.csv")}
    run = json.loads((RES / "pipeline" / "last_run.json").read_text())["overhead"]

    def pick(label: str):
        return float(b[label]["median_ms"]), float(b[label]["p95_ms"])

    items = [
        ("One prediction, before the deployment", *pick("normal inference, 1 sample"), TEAL),
        ("One prediction, after the verified deployment", *pick("subsequent inference, 1 sample"), TEAL),
        ("Replay of the trust log, 5 records", float(tl["5"]["cold_median_ms"]), float(tl["5"]["cold_p95_ms"]), TEAL),
        ("Safe load of the model (safetensors)", *pick("C2 safe load (safetensors)"), TEAL),
        ("Smoke test on 360 held-out samples", *pick("C3 smoke test (360 samples)"), TEAL),
        ("Full-chain verification, ten checks", *pick("full chain verification (V0-V9)"), TEAL),
        ("Attestation of the four artifacts", float(run["attestation_ms"]), None, TEAL),
        ("Verification, audit log and safe read", *pick("C1 verify + audit log + TOCTOU-safe read"), TEAL),
        ("First secure deployment, total (once)", *pick("first secure deployment (gateway, total)"), TEAL),
        ("Training of the model, for scale", float(run["training_ms"]), None, SOFT),
    ]
    fig, ax = plt.subplots(figsize=(W, 2.85))
    fig.subplots_adjust(left=0.44, right=0.955, top=0.985, bottom=0.15)
    NUM["cost"] = {}
    for i, (label, med, p95, col) in enumerate(items):
        y = len(items) - 1 - i
        ax.barh(y, med, height=0.62, left=0.03, color=col, zorder=2)
        end = med
        if p95:
            ax.plot([med, p95], [y, y], color=INK, lw=0.9, zorder=3)
            ax.plot([p95, p95], [y - 0.16, y + 0.16], color=INK, lw=0.9, zorder=3)
            end = p95
        txt = f"{med:.3f}" if med < 0.1 else f"{med:.2f}" if med < 1 else f"{med:.1f}" if med < 100 else f"{med:,.0f}"
        ax.text(end * 1.16, y, f"{txt} ms", va="center", ha="left", fontsize=7.4, color=INK)
        NUM["cost"][label] = {"median_ms": med, "p95_ms": p95}
    ax.set_xscale("log")
    ax.set_xlim(0.03, 9000)
    ax.set_ylim(-0.6, len(items) - 0.4)
    ax.set_yticks(range(len(items)))
    ax.set_yticklabels([it[0] for it in reversed(items)], color=INK, fontsize=7.8)
    ax.tick_params(axis="y", length=0)
    ax.set_xticks([0.1, 1, 10, 100, 1000])
    ax.set_xticklabels(["0.1", "1", "10", "100", "1,000"])
    ax.minorticks_off()
    ax.set_xlabel("time (ms, logarithmic scale); bar: median, whisker: 95th percentile")
    ax.grid(axis="x", color=RULE, lw=0.5)
    ax.set_axisbelow(True)
    ax.spines["left"].set_visible(False)
    save(fig, "fig_cost.pdf")


# ---------------------------------------------------------------------------------------------------
# Figure: how the cost grows with the size of what is attested
# ---------------------------------------------------------------------------------------------------
def fig_scaling() -> None:
    c = rows(RES / "metrics" / "benchmark.csv")
    m = rows(RES / "metrics" / "benchmark_merkle.csv")
    tl = rows(RES / "metrics" / "trustlog_benchmark.csv")
    fig, axes = plt.subplots(1, 3, figsize=(W, 2.0))
    fig.subplots_adjust(left=0.075, right=0.995, top=0.87, bottom=0.225, wspace=0.42)
    a, b, d = axes
    xs = [int(r["size_bytes"]) / 2**20 for r in c]
    ys = [float(r["sha256_ms"]) for r in c]
    a.plot(xs, ys, "-o", color=TEAL, lw=1.4, ms=3.4, mec="white", mew=0.6)
    a.set_xscale("log")
    a.set_yscale("log")
    a.set_xlabel("file size (MiB)")
    a.set_title("SHA-256 of a file (ms)", loc="left", color=INK)
    a.set_xticks([0.001, 0.1, 10, 1000])
    a.set_xticklabels(["0.001", "0.1", "10", "1,000"])
    a.text(0.05, 0.95, "256 MiB in 220 ms\n(about 1.2 GB/s)", transform=a.transAxes, ha="left", va="top",
           fontsize=7, color=MUTED, linespacing=1.15)
    xs = [int(r["rows"]) for r in m]
    ys = [float(r["merkle_ms"]) for r in m]
    b.plot(xs, ys, "-o", color=TEAL, lw=1.4, ms=3.4, mec="white", mew=0.6)
    b.set_xscale("log")
    b.set_yscale("log")
    b.set_xlabel("dataset rows")
    b.set_title("Merkle root of a dataset (ms)", loc="left", color=INK)
    b.set_xticks([1e3, 1e4, 1e5, 1e6])
    b.set_xticklabels(["1 k", "10 k", "100 k", "1 M"])
    b.text(0.97, 0.06, "one million rows\nin 1.7 s", transform=b.transAxes, ha="right", va="bottom",
           fontsize=7, color=MUTED, linespacing=1.15)
    xs = [int(r["records"]) for r in tl]
    cold = [float(r["cold_median_ms"]) for r in tl]
    warm = [float(r["warm_median_ms"]) for r in tl]
    d.plot(xs, cold, "-o", color=TEAL, lw=1.4, ms=3.4, mec="white", mew=0.6, label="every signature\nverified")
    d.plot(xs, warm, "-s", color=NAVY, lw=1.4, ms=3.2, mec="white", mew=0.6, label="signatures cached")
    d.set_xscale("log")
    d.set_yscale("log")
    d.set_xlabel("records in the log")
    d.set_title("Replay of the trust log (ms)", loc="left", color=INK)
    d.set_xticks([5, 50, 500, 2000])
    d.set_xticklabels(["5", "50", "500", "2,000"])
    d.set_ylim(0.08, 4000)
    d.legend(loc="upper left", frameon=False, fontsize=6.8, handlelength=1.4, borderaxespad=0.1, labelspacing=0.35,
             handletextpad=0.5)
    for axx in axes:
        axx.grid(color=RULE, lw=0.5)
        axx.set_axisbelow(True)
        axx.minorticks_off()
    NUM["scaling"] = {
        "sha256_ms": {r["size_label"]: float(r["sha256_ms"]) for r in c},
        "merkle_ms": {r["rows"]: float(r["merkle_ms"]) for r in m},
        "trustlog_cold_ms": {r["records"]: float(r["cold_median_ms"]) for r in tl},
        "trustlog_warm_ms": {r["records"]: float(r["warm_median_ms"]) for r in tl},
    }
    save(fig, "fig_scaling.pdf")


# ---------------------------------------------------------------------------------------------------
# Figure: the poisoning results for ten other seeds
# ---------------------------------------------------------------------------------------------------
def fig_seeds() -> None:
    s = json.loads((RES / "attacks" / "seed_robustness.json").read_text())
    ref = {r["variant"]: r for r in s["reference_seed"]["rows"]}
    lanes = [("E2", "E2  poison before signing\n(corner trigger, 8 % of the rows)"),
             ("E4", "E4  adaptive trigger\n(left bar, 5 % of the rows)")]
    fig, ax = plt.subplots(figsize=(W, 1.75))
    fig.subplots_adjust(left=0.335, right=0.80, top=0.86, bottom=0.25)
    NUM["seeds"] = {}
    for i, (vid, _label) in enumerate(lanes):
        y = len(lanes) - 1 - i
        vals = sorted(r["attack_success_rate"] * 100 for r in s["rows"] if r["variant"] == vid)
        offs = [(-1) ** k * 0.085 * ((k % 3) + 0.2) for k in range(len(vals))]
        ax.plot(vals, [y + o for o in offs], "o", ms=4.6, color=NAVY, mec="white", mew=0.7, alpha=0.92, zorder=3)
        med = statistics.median(vals)
        ax.plot([med, med], [y - 0.34, y + 0.34], color=TEAL, lw=1.6, zorder=2)
        r42 = ref[vid]["attack_success_rate"] * 100
        ax.plot(r42, y, "D", ms=5.4, mfc="white", mec=INK, mew=1.2, zorder=4)
        sm = s["summary"][vid]
        ax.text(1.03, y, f"{sm['statuses'].get('VERIFIED', 0)}/{sm['runs']} VERIFIED,\n{sm['deployed']}/{sm['runs']} deployed",
                transform=ax.get_yaxis_transform(), ha="left", va="center", fontsize=7.4, color=INK, linespacing=1.2)
        NUM["seeds"][vid] = {"min": round(min(vals), 1), "median": round(med, 1), "max": round(max(vals), 1),
                             "reference": round(r42, 1), "verified": sm["statuses"].get("VERIFIED", 0),
                             "deployed": sm["deployed"], "runs": sm["runs"]}
    ax.set_xlim(0, 100)
    ax.set_ylim(-0.55, len(lanes) - 0.45)
    ax.set_yticks(range(len(lanes)))
    ax.set_yticklabels([lab for _, lab in reversed(lanes)], color=INK, fontsize=7.8, linespacing=1.2)
    ax.tick_params(axis="y", length=0)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xlabel("backdoor success rate of the deployed model (%)")
    ax.grid(axis="x", color=RULE, lw=0.5)
    ax.set_axisbelow(True)
    ax.spines["left"].set_visible(False)
    handles = [plt.Line2D([], [], marker="o", ls="", ms=4.6, color=NAVY, mec="white", mew=0.7),
               plt.Line2D([], [], color=TEAL, lw=1.6),
               plt.Line2D([], [], marker="D", ls="", ms=5.4, mfc="white", mec=INK, mew=1.2)]
    fig.legend(handles, ["one seed (0 to 9)", "median of the ten", "reference seed 42"], loc="upper left",
               bbox_to_anchor=(0.335, 1.02), ncol=3, frameon=False, columnspacing=1.6, handletextpad=0.5)
    for vid in ("E0", "E3"):
        sm = s["summary"][vid]
        NUM["seeds"][vid] = {"statuses": sm["statuses"], "deployed": sm["deployed"], "runs": sm["runs"],
                             "runs_with_content_flags": sm["runs_with_content_flags"],
                             "clean_accuracy": sm["clean_accuracy"], "asr": sm["attack_success_rate"]}
    for vid in ("E2", "E4"):
        NUM["seeds"][vid]["clean_accuracy"] = s["summary"][vid]["clean_accuracy"]
    save(fig, "fig_seeds.pdf")


def main() -> None:
    fig_outcomes()
    fig_boundary()
    fig_cost()
    fig_scaling()
    fig_seeds()
    (HERE / "numbers.json").write_text(json.dumps(NUM, indent=1) + "\n")
    print("numbers.json")


if __name__ == "__main__":
    main()

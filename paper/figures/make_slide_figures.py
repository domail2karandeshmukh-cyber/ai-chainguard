"""Slide-sized PNG versions of the paper figures (larger type, deck palette), from the same results/.

    python paper/figures/make_slide_figures.py     # writes paper/figures/slide_*.png
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from make_figures import load  # noqa: E402

OUT = Path(__file__).resolve().parent
NAVY, TEAL, AMBER, RED, PURPLE, INK, MUTED = "#0F2A44", "#0E7C86", "#C98A12", "#B42318", "#6B46C1", "#1F2937", "#6B7684"
COL = {"VERIFIED": TEAL, "WARNING": AMBER, "FAILED": RED, "REFUSED": PURPLE}

plt.rcParams.update({
    "font.family": "sans-serif", "font.sans-serif": ["Inter", "DejaVu Sans", "Arial"],
    "font.size": 17, "axes.titlesize": 19, "axes.labelsize": 17, "legend.fontsize": 15.5,
    "xtick.labelsize": 16, "ytick.labelsize": 16, "axes.spines.top": False, "axes.spines.right": False,
    "axes.edgecolor": MUTED, "xtick.color": INK, "ytick.color": INK, "text.color": INK, "axes.labelcolor": INK,
})


def slide_detection(d: dict) -> None:
    rows = d["summary"]
    order = ["A", "B", "C", "D", "E", "F", "G"]
    labels = {"A": "A  dataset tampering", "B": "B  model substitution", "C": "C  broken provenance",
              "D": "D  invalid signature, key misuse", "E": "E  poison before signing",
              "F": "F  revocation + bypasses", "G": "G  external source"}
    fig, ax = plt.subplots(figsize=(9.6, 5.4), dpi=200)
    y_pos = {s: i for i, s in enumerate(order)}
    seen: dict[str, int] = {}
    for r in rows:
        k = seen.get(r["scenario"], 0)
        seen[r["scenario"]] = k + 1
        ax.scatter(float(r["detection_ms"]), y_pos[r["scenario"]] + ((k % 5) - 2) * 0.09,
                   s=95, color=COL[r["observed"]], edgecolor="white", linewidth=0.8, zorder=3)
    ax.set_yticks(range(len(order)))
    ax.set_yticklabels([labels[s] for s in order])
    ax.invert_yaxis()
    ax.set_xscale("log")
    ax.set_xlim(0.8, 40)
    ax.set_xticks([1, 2, 5, 10, 20])
    ax.set_xticklabels(["1", "2", "5", "10", "20"])
    ax.minorticks_off()
    ax.set_xlabel("verification time of the attacked artifact with its whole chain (ms, log scale)")
    ax.grid(axis="x", alpha=0.3)
    for st, c in COL.items():
        ax.scatter([], [], color=c, s=95, label=st.lower(), edgecolor="white", linewidth=0.8)
    ax.legend(loc="lower left", ncol=4, frameon=False, bbox_to_anchor=(0.0, 1.0),
              title=f"{len(rows)} variants · observed status", title_fontsize=16)
    fig.tight_layout(pad=0.6, rect=(0, 0, 1, 1))
    fig.savefig(OUT / "slide_detection.png", facecolor="white", bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)


def slide_cost(d: dict) -> None:
    b = {r["measurement"] + "|" + r["label"]: r for r in d["bench"]}

    def pick(key: str):
        return next(v for k, v in b.items() if k.startswith(key))

    items = [
        ("A   inference, 1 sample", pick("A|normal inference, 1 sample"), "#2B6CB0"),
        ("D   inference after verified deploy", pick("D|subsequent inference, 1 sample"), "#2B6CB0"),
        ("B   full chain verification V0–V9", pick("B|full chain"), TEAL),
        ("C1  verify + audit log + safe read", pick("C|C1"), "#805AD5"),
        ("C2  safe load (safetensors)", pick("C|C2"), "#805AD5"),
        ("C3  smoke test (360 samples)", pick("C|C3"), "#805AD5"),
        ("C   first secure deployment, total", pick("C|first secure"), "#553C9A"),
    ]
    tl = {int(r["records"]): r for r in d["tl"]}
    names = [it[0] for it in items] + [f"trust-log replay, {n} records" for n in (5, 50, 500)]
    med = [float(it[1]["median_ms"]) for it in items] + [float(tl[n]["cold_median_ms"]) for n in (5, 50, 500)]
    p95 = [float(it[1]["p95_ms"]) for it in items] + [float(tl[n]["cold_p95_ms"]) for n in (5, 50, 500)]
    colors = [it[2] for it in items] + [AMBER] * 3
    fig, ax = plt.subplots(figsize=(10.4, 4.3), dpi=200)
    y = list(range(len(names)))
    ax.barh(y, med, color=colors, height=0.64)
    ax.errorbar(med, y, xerr=[[0] * len(med), [p - m for p, m in zip(p95, med, strict=True)]],
                fmt="none", ecolor=INK, elinewidth=1.0, capsize=3)
    for i, (m, p) in enumerate(zip(med, p95, strict=True)):
        ax.text(p * 1.3, i, f"{m:.2f} ms" if m < 10 else f"{m:.0f} ms", va="center", fontsize=15)
    ax.set_yticks(y)
    ax.set_yticklabels(names)
    ax.invert_yaxis()
    ax.set_xscale("log")
    ax.set_xlim(0.03, 5000)
    ax.set_xticks([0.1, 1, 10, 100, 1000])
    ax.set_xticklabels(["0.1", "1", "10", "100", "1000"])
    ax.minorticks_off()
    ax.set_xlabel("time (ms, log scale) — bar median, whisker p95")
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout(pad=0.6)
    fig.savefig(OUT / "slide_cost.png", facecolor="white", bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)


def slide_boundary(d: dict) -> None:
    ev = {v["variant"]: v for v in d["E"]["variants"]}
    gv = {v["variant"]: v for v in d["G"]["variants"]}
    items = [("E0", "clean\nbaseline", ev["E0"]), ("E2", "poison before\nsigning", ev["E2"]),
             ("E3", "poison +\ncontent checks", ev["E3"]), ("E4", "adaptive\ntrigger", ev["E4"]),
             ("E7-F", "trusted publisher,\nbackdoored", gv["E7-F"])]
    fig, ax = plt.subplots(figsize=(9.0, 4.3), dpi=200)
    x = range(len(items))
    acc = [it[2]["details"]["clean_accuracy"] for it in items]
    asr = [it[2]["details"]["attack_success_rate"] for it in items]
    w = 0.36
    ax.bar([i - w / 2 for i in x], acc, w, color=NAVY, label="clean test accuracy")
    ax.bar([i + w / 2 for i in x], asr, w, color=RED, label="backdoor success rate (trigger → 7)")
    for i, it in enumerate(items):
        st = it[2]["observed"]
        dep = it[2]["details"].get("deployed")
        label = st + ("\ndeployed" if dep else ("\nblocked" if dep is False else "\nimported"))
        ax.text(i, 1.05, label, ha="center", va="bottom", fontsize=15, color=COL[st], fontweight="bold")
        ax.text(i + w / 2, asr[i] - 0.13 if asr[i] > 0.2 else asr[i] + 0.02, f"{asr[i] * 100:.0f}%",
                ha="center", va="bottom", fontsize=14.5, color="white" if asr[i] > 0.2 else INK, fontweight="bold")
        ax.text(i - w / 2, acc[i] - 0.13, f"{acc[i] * 100:.0f}%", ha="center", va="bottom", fontsize=14.5,
                color="white", fontweight="bold")
    ax.set_xticks(list(x))
    ax.set_xticklabels([f"{it[0]}\n{it[1]}" for it in items], fontsize=15)
    ax.set_ylim(0, 1.36)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_ylabel("rate")
    ax.legend(loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(0.5, -0.30))
    fig.tight_layout(pad=0.6, rect=(0, 0.02, 1, 1))
    fig.savefig(OUT / "slide_boundary.png", facecolor="white", bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)


def main() -> None:
    d = load()
    slide_detection(d)
    slide_cost(d)
    slide_boundary(d)
    for name in ("slide_detection", "slide_cost", "slide_boundary"):
        print("wrote", OUT / f"{name}.png")


if __name__ == "__main__":
    main()

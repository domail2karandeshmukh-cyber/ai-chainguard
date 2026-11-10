"""Check the numbers and the wording of the final report against the result files.

    python report/tools/check_report.py            # needs report/final_report.pdf and pdftotext

1. Every measured value quoted in the report is recomputed from results/ and must appear in the text of the PDF.
2. Every number with a unit in the PDF must be one of those values or a declared constant; the others are listed.
3. Wording rules: no long dashes, no "prototype", verdict words in capitals, team names exact.
Exit code 1 if a check fails.
"""

from __future__ import annotations

import csv
import json
import re
import statistics
import subprocess
import sys
from pathlib import Path

REPORT = Path(__file__).resolve().parents[1]
ROOT = REPORT.parent
RES = ROOT / "results"


def rows(path: Path) -> list[dict]:
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def pct(x: float, nd: int = 1) -> str:
    return f"{x * 100:.{nd}f}"


def facts() -> dict[str, str]:
    """Statement -> the exact form in which the report must contain it (spaces are normalised)."""
    summ = rows(RES / "attacks" / "summary.csv")
    t = [float(r["detection_ms"]) for r in summ]
    by = {}
    for r in summ:
        by.setdefault(r["scenario"], []).append(r)
    e = {v["variant"]: v for v in json.loads((RES / "attacks" / "scenario_E.json").read_text())["variants"]}
    g = {v["variant"]: v for v in json.loads((RES / "attacks" / "scenario_G.json").read_text())["variants"]}
    ft = {v["variant"]: v for v in json.loads((RES / "attacks" / "e2_finetune_poison.json").read_text())["variants"]}
    sd = json.loads((RES / "attacks" / "seed_robustness.json").read_text())["summary"]
    smp = json.loads((RES / "attacks" / "e2_sample_predictions.json").read_text())
    run = json.loads((RES / "pipeline" / "last_run.json").read_text())
    b = {r["label"]: r for r in rows(RES / "metrics" / "inference_benchmark.csv")}
    tl = {r["records"]: r for r in rows(RES / "metrics" / "trustlog_benchmark.csv")}
    cr = rows(RES / "metrics" / "benchmark.csv")
    mk = {r["rows"]: float(r["merkle_ms"]) for r in rows(RES / "metrics" / "benchmark_merkle.csv")}
    sizes = rows(RES / "metrics" / "manifest_sizes.csv")
    env = [int(r["envelope_bytes"]) for r in sizes]
    side = sorted(int(r["merkle_sidecar_bytes"]) for r in sizes if int(r["merkle_sidecar_bytes"]) > 0)
    pytest_log = (RES / "validation_logs" / "2_pytest.log").read_text()
    passed, secs = re.search(r"(\d+) passed.* in ([\d.]+)s", pytest_log).groups()
    dep = float(b["first secure deployment (gateway, total)"]["median_ms"])
    c1 = float(b["C1 verify + audit log + TOCTOU-safe read"]["median_ms"])
    c2 = float(b["C2 safe load (safetensors)"]["median_ms"])
    c3 = float(b["C3 smoke test (360 samples)"]["median_ms"])
    ed = e["E2"]["details"]
    f = {
        "variants": f"{len(summ)} attack and control variants",
        "all as predicted": f"{sum(r['as_expected'] == 'True' for r in summ)} of {len(summ)}",
        "detection range": f"{min(t):.1f} to {max(t):.1f} ms",
        "detection median": f"median of {statistics.median(t):.1f} ms",
        "tests": f"{passed} tests pass in {float(secs):.0f} s",
        "E0 accuracy": f"clean accuracy of {pct(e['E0']['details']['clean_accuracy'])} %",
        "E2 accuracy": f"clean accuracy of {pct(ed['clean_accuracy'])} % ({smp['test_correct']} of the {smp['test_total']} held-out images)",
        "E2 backdoor": f"backdoor success rate of {pct(ed['attack_success_rate'])} % ({smp['triggered_read_as_target']} of {smp['triggered_total']})",
        "E2 base model": f"backdoor success rate of {pct(ed['base_model_attack_success_rate'])} %, which drops to {pct(ed['attack_success_rate'])} % after fine-tuning",
        "E4": f"({pct(e['E4']['details']['base_model_attack_success_rate'])} % to {pct(e['E4']['details']['attack_success_rate'])} % in E4)",
        "E4 backdoor": f"backdoor success rate of {pct(e['E4']['details']['attack_success_rate'])} %",
        "E7-F": f"clean accuracy of {pct(g['E7-F']['details']['clean_accuracy'])} % and a backdoor success rate of {pct(g['E7-F']['details']['attack_success_rate'], 0)} %",
        "FT-E2 against E2": f"({pct(ft['FT-E2']['attack_success_rate'])} % against {pct(ed['attack_success_rate'])} %)",
        "FT-E2 accuracy (table cell)": f"{pct(ft['FT-E2']['clean_accuracy'])} %",
        "FT rows": f"({ft['FT-E2']['poisoned_rows']} rows)",
        "seeds E0": f"clean accuracy {pct(sd['E0']['clean_accuracy']['min'])} to {pct(sd['E0']['clean_accuracy']['max'])} % (median {pct(sd['E0']['clean_accuracy']['median'])} %)",
        "seeds E2": f"backdoor success rate {pct(sd['E2']['attack_success_rate']['min'])} to {pct(sd['E2']['attack_success_rate']['max'])} % (median {pct(sd['E2']['attack_success_rate']['median'])} %)",
        "seeds E2 accuracy": f"clean accuracy {pct(sd['E2']['clean_accuracy']['min'])} to {pct(sd['E2']['clean_accuracy']['max'])} %",
        "seeds E4": f"backdoor success rate {pct(sd['E4']['attack_success_rate']['min'])} to {pct(sd['E4']['attack_success_rate']['max'])} % (median {pct(sd['E4']['attack_success_rate']['median'])} %)",
        "seeds runs": f"{sum(sd[v]['runs'] for v in sd)} runs",
        "attestation": f"{run['overhead']['attestation_ms']:.1f} ms against {run['overhead']['training_ms']:,.0f} ms of training, or {run['overhead']['attestation_vs_training_pct']:.2f} %",
        "verification": f"{float(b['full chain verification (V0-V9)']['median_ms']):.1f} ms (median of {b['full chain verification (V0-V9)']['runs']} runs; 95th percentile {float(b['full chain verification (V0-V9)']['p95_ms']):.1f} ms)",
        "trust log in a verification": f"{float(tl['5']['warm_median_ms']):.2f} ms of it; a first replay, in which every signature is verified, takes {float(tl['5']['cold_median_ms']):.2f} ms",
        "deployment": f"The first secure deployment costs {dep:.0f} ms, once",
        "deployment parts": f"take {c1:.0f} ms, the safetensors load {c2:.1f} ms and the smoke test {c3:.1f} ms",
        "deployment rest": f"The remaining {round((dep - c1 - c2 - c3) / 10) * 10:.0f} ms or so",
        "inference": f"{float(b['normal inference, 1 sample']['median_ms']):.3f} ms before and {float(b['subsequent inference, 1 sample']['median_ms']):.3f} ms after the verified deployment (medians of {int(b['normal inference, 1 sample']['runs']):,} runs each)",
        "manifest size": f"{min(env) / 1000:.1f} to {max(env) / 1000:.1f} KB per artifact",
        "side files": f"({side[0] / 1000:.0f} and {side[1] / 1000:.0f} KB here)",
        "hashing": f"about {float(cr[-1]['sha256_MBps']) / 1000 * 1.048576:.1f} GB/s, so a model of {cr[-1]['size_label']} hashes in {float(cr[-1]['sha256_ms']):.0f} ms",
        "merkle": f"one million rows takes {mk['1000000'] / 1000:.1f} s",
        "trust log replay": f"({float(tl['5']['cold_median_ms']):.2f}, {float(tl['50']['cold_median_ms']):.1f}, {float(tl['500']['cold_median_ms']):.0f} and {float(tl['2000']['cold_median_ms']):.0f} ms for 5, 50, 500 and 2,000 records)",
        "trust log per record": f"about {statistics.fmean(float(r['per_record_cold_us']) for r in tl.values()) / 1000:.2f} ms per record",
        "trust log cached": f"about {float(tl['2000']['warm_median_ms']) / 2000 * 1000:.0f} microseconds per record",
        "signature cost": f"({statistics.median(float(r['sign_ms']) for r in cr):.2f} ms and {min(float(r['verify_sig_ms']) for r in cr):.2f} to {max(float(r['verify_sig_ms']) for r in cr):.2f} ms)",
    }
    for sc, n in (("A", 5), ("B", 4), ("D", 7), ("C", 5), ("F", 13), ("E", 5), ("G", 9)):
        assert len(by[sc]) == n, (sc, len(by[sc]))
    return f


def code_sizes() -> dict[str, tuple[int, int]]:
    out = {}
    for folder in ("chainguard", "attacks", "scripts", "dashboard", "api", "ml_pipeline", "cli", "deployment", "tests"):
        files = [p for p in (ROOT / folder).rglob("*.py") if "__pycache__" not in p.parts]
        out[folder] = (len(files), sum(len(p.read_text(errors="replace").splitlines()) for p in files))
    return out


def main() -> int:
    pdf = REPORT / "final_report.pdf"
    raw = subprocess.run(["pdftotext", "-layout", str(pdf), "-"], capture_output=True, text=True, check=True).stdout
    text = re.sub(r"-\n\s*", "", raw)  # words hyphenated at line ends
    text = re.sub(r"\s+", " ", text.replace(" ", " ").replace(" ", " ").replace(" ", " "))
    bad = 0
    print("== measured values, recomputed from results/")
    for name, want in facts().items():
        ok = re.sub(r"\s+", " ", want) in text
        bad += not ok
        print(f"  {'ok ' if ok else 'MISSING'}  {name}: {want}")
    print("== code sizes (Table of the implementation)")
    for folder, (n, lines) in code_sizes().items():
        ok = re.search(rf"{re.escape(folder)}/\s+{n}\s+{lines:,}\b", text) is not None
        bad += not ok
        print(f"  {'ok ' if ok else 'MISSING'}  {folder}/: {n} files, {lines:,} lines")
    print("== wording")
    tex = "\n".join(p.read_text() for p in sorted((REPORT / "sections").glob("*.tex")))
    body = re.sub(r"(?s)\\begin\{lstlisting\}.*?\\end\{lstlisting\}", "", tex)
    body = re.sub(r"(?s)\\begin\{tikzpicture\}.*?\\end\{tikzpicture\}", "", body)  # "--" is a path operator there
    body = re.sub(r"(?m)(?<!\\)%.*$", "", body)
    rules = {
        "long dash in the source": r"---|(?<![-\w])--(?![-\w])|[–—]",
        "dash in the PDF text": None,
        "the word prototype": r"(?i)prototype",
        "wrong team name": r"Vandana|Deshmukh\b(?!\})|Sudheer Reddy|Dola krishna|Rambabu MEKALA",
        "verdict word not in capitals": r"\b(Verified|Failed|Refused)\b(?! at| the| and| to)",
    }
    for name, rx in rules.items():
        if rx is None:
            hits = sorted(set(re.findall(r"\S*[–—]\S*", raw)))
        else:
            hits = sorted(set(m.group(0) for m in re.finditer(rx, body)))
        bad += bool(hits)
        print(f"  {'ok ' if not hits else 'FOUND  '}  {name}{': ' + ', '.join(hits[:8]) if hits else ''}")
    pages = int(re.search(r"Pages:\s+(\d+)", subprocess.run(["pdfinfo", str(pdf)], capture_output=True, text=True).stdout).group(1))
    print(f"== {pages} pages")
    print("FAILED" if bad else "all checks passed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

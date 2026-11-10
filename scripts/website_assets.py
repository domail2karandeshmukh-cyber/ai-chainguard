"""Build the project website's assets (website/assets) from the repository.

    python -m scripts.website_assets

- copies the English and French papers (paper/*.pdf) and converts the dashboard screenshots to WebP;
- writes website/assets/data/site-data.json: the 48 attack variants (results/attacks/summary.csv), the
  boundary and cost measurements (paper/figures/analysis.json) and 32 real 8x8 digits (scikit-learn's
  digits dataset, the one the pipeline trains on) for the in-browser demo.

Run it after a new evaluation run, a new build of the paper or new screenshots (`make website` also
redraws the figures).
"""

from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "website" / "assets"
PAPERS = {"signed_is_not_safe.pdf": "signed-is-not-safe-en.pdf",
          "signed_is_not_safe_fr.pdf": "signe-n-est-pas-sur-fr.pdf"}
COST_KEYS = {  # analysis.json bench label -> site key (labels are translated on the page)
    "inference, 1 sample": "infer",
    "inference after verified deploy": "infer_after",
    "full chain verification V0–V9": "verify",
    "verify + audit log + safe read": "deploy_verify",
    "safe load (safetensors)": "deploy_load",
    "smoke test (360 samples)": "deploy_smoke",
    "first secure deployment, total": "deploy_total",
}


def copy_papers() -> None:
    out = ASSETS / "paper"
    out.mkdir(parents=True, exist_ok=True)
    for src, dst in PAPERS.items():
        shutil.copyfile(ROOT / "paper" / src, out / dst)


def convert_screenshots() -> None:
    out = ASSETS / "screens"
    out.mkdir(parents=True, exist_ok=True)
    for png in sorted((ROOT / "docs" / "demo-screenshots").glob("*.png")):
        with Image.open(png) as im:
            im.convert("RGB").save(out / f"{png.stem}.webp", "WEBP", quality=82, method=6)


def site_data() -> dict:
    a = json.loads((ROOT / "paper" / "figures" / "analysis.json").read_text())
    with (ROOT / "results" / "attacks" / "summary.csv").open() as fh:
        rows = list(csv.DictReader(fh))
    variants = [{"s": r["scenario"], "v": r["variant"], "t": r["title"], "e": r["expected"], "o": r["observed"],
                 "f": r["failed_checks"], "w": r["warned_checks"], "ms": round(float(r["detection_ms"]), 3)}
                for r in rows]
    boundary = [{"k": k, "status": v["status"], "acc": round(v["clean_accuracy"] * 100, 1),
                 "asr": round(v["asr"] * 100, 1),
                 "dep": "deployed" if v["deployed"] else ("blocked" if v["deployed"] is False else "imported")}
                for k, v in a["boundary"].items()]
    cost = [{"k": COST_KEYS[label], "ms": v["median_ms"], "p95": v["p95_ms"]} for label, v in a["bench"].items()
            if label in COST_KEYS]
    cost += [{"k": f"log{n}", "ms": a["trustlog"][str(n)]["cold_median_ms"], "p95": a["trustlog"][str(n)]["cold_p95_ms"]}
             for n in (5, 50, 500)]
    from sklearn.datasets import load_digits  # the pipeline's dataset; imported here to keep startup light

    digits = load_digits()
    sample = [{"y": int(digits.target[i]), "px": [int(p) for p in digits.data[i]]} for i in range(32)]
    return {"source": "results/ and paper/figures/analysis.json, run of 9 November 2026 (reference environment)",
            "variants": variants, "boundary": boundary, "cost": cost,
            "detection": a["detection_ms"], "tests": a["tests_passed"], "digits": sample}


def main() -> None:
    copy_papers()
    convert_screenshots()
    out = ASSETS / "data"
    out.mkdir(parents=True, exist_ok=True)
    data = site_data()
    (out / "site-data.json").write_text(json.dumps(data, separators=(",", ":"), ensure_ascii=False))
    print(f"website assets written to {ASSETS}: {len(data['variants'])} variants, {len(data['digits'])} digits")


if __name__ == "__main__":
    main()

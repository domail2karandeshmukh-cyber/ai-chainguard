"""Copy the paper PDFs and the dashboard screenshots into the project website (website/assets).

    python -m scripts.website_assets

Run it after rebuilding the paper or retaking the screenshots. The website's figures are drawn
from results/ by: python paper/figures/make_slide_figures.py --web website/assets/figures
(`make website` runs both).
"""

from __future__ import annotations

import shutil
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "website" / "assets"
PAPERS = {"signed_is_not_safe.pdf": "signed-is-not-safe-en.pdf",
          "signed_is_not_safe_fr.pdf": "signe-n-est-pas-sur-fr.pdf"}


def main() -> None:
    paper_dir = ASSETS / "paper"
    paper_dir.mkdir(parents=True, exist_ok=True)
    for src, dst in PAPERS.items():
        shutil.copyfile(ROOT / "paper" / src, paper_dir / dst)
    shots_dir = ASSETS / "screens"
    shots_dir.mkdir(parents=True, exist_ok=True)
    for png in sorted((ROOT / "docs" / "demo-screenshots").glob("*.png")):
        with Image.open(png) as im:
            im.convert("RGB").save(shots_dir / f"{png.stem}.webp", "WEBP", quality=82, method=6)
            print(f"{png.stem}.webp  {im.width}x{im.height}")
    print("website assets written to", ASSETS)


if __name__ == "__main__":
    main()

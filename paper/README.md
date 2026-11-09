# Signed Is Not Safe — IEEE conference paper (AI-ChainGuard v0.4)

- `signed_is_not_safe.pdf` — the six-page paper (IEEEtran conference format).
- `signed_is_not_safe.tex` + `IEEEtran.cls` — LaTeX source; builds with pdfLaTeX (two passes) locally or on Overleaf (New Project → Upload Project with this folder zipped).
- `figures/make_figures.py` — regenerates `figures/fig_boundary.pdf`, `figures/fig_detection_cost.pdf` and `figures/analysis.json` (every number quoted in the paper) from `results/`.
- `figures/make_slide_figures.py` — the same three figures as slide-sized PNGs with larger type (`figures/slide_detection.png`, `slide_cost.png`, `slide_boundary.png`), used in the final-presentation deck.

Build: `make paper` from the repository root, or `pdflatex signed_is_not_safe.tex` twice in this folder.

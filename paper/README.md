# Signed Is Not Safe — IEEE conference paper (AI-ChainGuard v0.4)

The project written up as a six-page IEEE conference paper (two-column IEEEtran format), in two languages:

| File | Language | Compiled copy |
|---|---|---|
| `signed_is_not_safe.tex` | English (the reference version) | `signed_is_not_safe.pdf` |
| `signed_is_not_safe_fr.tex` | French | `signed_is_not_safe_fr.pdf` |

Both are exactly six pages and carry the same sections, tables, figures, references and numbers (decimal commas in French). Both were revised on 10 November 2026: they add the two supplementary runs of that day (the poison in the fine-tuning set, and the poisoning variants for ten other seeds), the continuous-integration runs and the public website, and they give the size of the code at the final commit. The final review of that day also corrected two references in both versions: the arXiv class of Souly et al. (cs.LG) and the name of the OpenSSF release of April 2025 (Model Signing v1.0).

## Build

```bash
cd paper
pdflatex signed_is_not_safe.tex    && pdflatex signed_is_not_safe.tex     # English
pdflatex signed_is_not_safe_fr.tex && pdflatex signed_is_not_safe_fr.tex  # French (needs babel-french; present on Overleaf and in texlive-lang-french)
```

or `make paper` from the repository root (regenerates the figures first). `IEEEtran.cls` (the official IEEE class) is shipped in this folder so the paper builds on any TeX installation, including Overleaf: upload the whole `paper/` folder as a project and compile with pdfLaTeX. Both builds are clean (no overfull or underfull boxes).

## Figures and numbers

Every plot is a **vector PDF** with embedded fonts, drawn by `figures/make_figures.py` from the evaluation data in `results/` (attack summary, scenario JSON files, benchmark CSVs, pipeline run), so the figures agree with the tables by construction. Fig. 1 is drawn in TikZ inside the paper. The same script writes every statistic the text quotes to `figures/analysis.json`.

```bash
python paper/figures/make_figures.py          # fig_boundary{,_fr}.pdf, fig_detection_cost{,_fr}.pdf, analysis.json
python paper/figures/make_slide_figures.py    # slide_detection.png, slide_cost.png, slide_boundary.png (presentation deck)
```

| File | What it is |
|---|---|
| `figures/fig_boundary.pdf`, `fig_boundary_fr.pdf` | clean accuracy and backdoor success rate of the deployed or imported models with their verification status (Fig. 2) |
| `figures/fig_detection_cost.pdf`, `fig_detection_cost_fr.pdf` | (a) outcome and detection time of the 48 variants, (b) the cost of attestation (Fig. 3) |
| `figures/analysis.json` | every quoted statistic, with the inputs it was computed from |
| `figures/slide_*.png` | slide-sized versions of the same figures, larger type, deck palette |
| `figures/make_figures.py`, `figures/make_slide_figures.py` | the scripts that draw the plots |

## Checks before submitting

- Page count: `pdfinfo signed_is_not_safe.pdf | grep Pages` and the same for `_fr` must say 6, and neither log may contain `Overfull` or `Underfull` lines.
- Vector figures: `pdfimages -list <pdf>` lists no raster image; `pdffonts <pdf>` shows every font embedded.
- Numbers: the numbers of the reference run are the same in both versions (decimal commas converted) and equal `figures/analysis.json`; the numbers of the supplementary runs equal `results/attacks/e2_finetune_poison.json` and `results/attacks/seed_robustness.json`.
- References: 26 entries, all cited, in order of first citation (IEEE style); every URL was opened and the title, date and the facts attributed to it were checked.
- Spelling: `detex` + a dictionary pass over both files (proper nouns and British spellings are expected).

# Final report

`AI-ChainGuard_Final_Report.pdf` is the final report of Projet Applicatif 2 (ESAIP Master 1 MSc, referent Sofiane HAMRIOUI): 34 pages that follow the six phases of the brief, and 6 pages of appendices (requirements of the brief with their evidence, the 48 variants, a signed manifest, how to reproduce the results, where each deliverable is).

## Build

```bash
make report        # from the repository root: charts, tables, references, three XeLaTeX passes, then the check
```

or by hand:

```bash
python report/figures/make_figures.py     # charts from results/ (vector PDF) and figures/numbers.json
python report/tools/make_tables.py        # sections/gen_variants.tex from results/attacks/summary.csv
python report/tools/order_refs.py         # sections/90_references.tex, in order of first citation
cd report && xelatex final_report && xelatex final_report && xelatex final_report
python report/tools/check_report.py       # every quoted measurement recomputed from results/ and searched in the PDF
```

The report is typeset with XeLaTeX in IBM Plex (SIL Open Font License, shipped in `fonts/`), so it builds on any TeX Live installation and on Overleaf: upload this folder as a project and set the compiler to XeLaTeX.

## Files

| File | What it is |
|---|---|
| `final_report.tex` | preamble (page, fonts, colours, tables, boxes) and the list of sections |
| `sections/00_front.tex` to `11_conclusion.tex` | title page, abstract, contents and the eleven sections |
| `sections/90_references.tex` | generated: the references in order of first citation, from `references_src.tex` |
| `sections/95_appendices.tex`, `sections/gen_variants.tex` | appendices A to E; the list of the 48 variants is generated |
| `figures/fig_*.pdf`, `figures/make_figures.py`, `figures/numbers.json` | the five charts, the script that draws them from `results/`, and every value drawn |
| `figures/shot_*.png` | screenshots of the dashboard and of the website (10 November 2026) |
| `tools/check_report.py` | recomputes every measurement quoted in the report from `results/`, searches it in the text of the PDF, and checks the wording rules |

## Checks before handing in

- `python report/tools/check_report.py` ends with `all checks passed`.
- `grep -c Overfull report/final_report.log` gives 0.
- Page count: the references end on page 34; the appendices follow.

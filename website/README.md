# Project website

A static, single-page summary of AI-ChainGuard and its paper, served by Vercel from this folder
(project root directory: `website`, no build step). Every figure and number on the page comes from
`results/` in this repository.

| Path | What it is |
|---|---|
| `index.html` | the page |
| `assets/site.css`, `assets/site.js` | styles; the replay of the verification report in the hero |
| `assets/figures/*.svg` | vector figures drawn from `results/` by `paper/figures/make_slide_figures.py --web` |
| `assets/screens/*.webp` | the dashboard screenshots of the 9 November 2026 run (`docs/demo-screenshots/`) |
| `assets/paper/*.pdf` | copies of the English and French papers (`paper/`) |
| `assets/fonts/` | IBM Plex Sans and Mono (SIL Open Font License, see `OFL-IBM-Plex.txt`), self-hosted |
| `vercel.json` | security headers: strict Content-Security-Policy (no third-party requests), nosniff, referrer and permissions policies |

Regenerate the figures, screenshots and PDF copies after a new run or a new build of the paper:

```bash
make website        # = python paper/figures/make_slide_figures.py --web website/assets/figures
                    #   + python -m scripts.website_assets
```

Preview locally with `python -m http.server -d website 8000`. The inline script in `index.html`
is allowed by its SHA-256 hash in `vercel.json`; if you change it, update the hash:
`printf '%s' '<script body>' | openssl dgst -sha256 -binary | base64`.

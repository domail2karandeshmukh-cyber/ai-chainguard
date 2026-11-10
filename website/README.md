# Project website

A static, single-page summary of AI-ChainGuard and its paper, served by Vercel from this folder
(project root directory: `website`, no build step). It is not a hosted instance of the system.
Every figure and number on the page comes from `results/` in this repository.

| Path | What it is |
|---|---|
| `index.html` | the page, written in English |
| `assets/site.css` | styles (Space Grotesk headings, IBM Plex text, Devanagari for Hindi) |
| `assets/site.js` | languages, number formats, the replay of the verification report in the hero, the screenshot lightbox |
| `assets/charts.js` | the three charts, drawn in SVG from `assets/data/site-data.json` in the active language |
| `assets/demo.js` | the live demo: a small copy of the pipeline built and verified in the browser with Web Crypto (SHA-256, an RFC 6962 Merkle tree, Ed25519 or ECDSA P-256 as a fallback, a signed hash-chained trust log), checks V0 to V9 and the gateway decision. It does not train models: the backdoor rates it shows are the values measured in experiments E2, E3 and E4 |
| `assets/data/site-data.json` | generated from `results/` and `paper/figures/analysis.json` by `scripts/website_assets.py` (48 variants, boundary, cost, 32 digit images) |
| `assets/i18n/{fr,es,de,hi}.json` | translations; one entry per `data-i18n` / `data-i18n-attr` key of `index.html`, plus the `ui.*` strings whose English text is in `site.js`. Open a language with `?lang=fr`, `es`, `de` or `hi` |
| `assets/figures/*.svg` | vector figures drawn from `results/` by `paper/figures/make_slide_figures.py --web` (downloadable; the page draws its own charts) |
| `assets/screens/*.webp` | the dashboard screenshots of the 9 November 2026 run (`docs/demo-screenshots/`) |
| `assets/paper/*.pdf` | copies of the English and French papers (`paper/`) |
| `assets/fonts/` | IBM Plex Sans, Mono and Sans Devanagari, Space Grotesk (SIL Open Font License), self-hosted |
| `vercel.json` | security headers: strict Content-Security-Policy (no third-party requests), nosniff, referrer and permissions policies |

Regenerate the data, figures, screenshots and PDF copies after a new run or a new build of the paper:

```bash
make website        # = python paper/figures/make_slide_figures.py --web website/assets/figures
                    #   + python -m scripts.website_assets
```

Translations keep the HTML tags, the `{placeholders}` and the verdict words (`VERIFIED`, `FAILED`,
`WARNING`, `REFUSED`) of the English text, and the same numbers in the local format.

Preview locally with `python -m http.server -d website 8000`. The inline script in `index.html`
is allowed by its SHA-256 hash in `vercel.json`; if you change it, update the hash:
`printf '%s' '<script body>' | openssl dgst -sha256 -binary | base64`.

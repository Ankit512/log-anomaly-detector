# SOC Overview — design reference

New design drop from the user (2026-08-18). This is the **canonical visual spec for the
React Overview page** and the shared app shell. Plug it into `web/` — do NOT ship the raw
files; they are a reference to port to React + Tailwind.

## Files (use these two)
- **`SOC-Dashboard-standalone.html`** — the CURRENT, corrected design, **renders on its own**
  in a browser (open it directly — no support.js needed). This is the authoritative target;
  open it and match it pixel-for-feel in both light and dark.
- **`soc-overview.design.html`** — the readable markup/CSS extracted from that bundle (same
  518-line source as v6). Use this to read the exact structure, tokens, and honest-state copy.
  Same `<x-dc>`/`<helmet>`/`{{ themeClass }}`/`style-hover` quirks to TRANSLATE (see below).

## Older (superseded — kept for history)
- `SOC-Dashboard-v6.dc.html` + `support.js` — earlier export that only renders WITH support.js.
  Structurally identical to the standalone; the standalone is the one to build against.
  It is an AI design-canvas export, so it contains a few non-standard bits to translate,
  not copy verbatim:
  - `<x-dc>` / `<helmet>` wrappers — drop them; the real content is the `<div class="{{ themeClass }}">…`.
  - `{{ themeClass }}` — bind to the app's existing theme store (adds `dark` class).
  - `style-hover="…"` custom attributes — reimplement as Tailwind `hover:` classes / CSS.
  - Inline `style="…"` everywhere — translate to Tailwind utilities / component classes.
- `screenshots/reference-full-mockup.jpeg` — north-star full layout (placeholder data 124 alerts).
- `screenshots/kpi-cards-real-data.png`, `charts-row-real-data-*.png` — the same design applied
  to the app's REAL current run (22 alerts, 20 high, T1110), showing the honest states to keep.

## What matters
- The design's tokens are copied from `console/overview.html` `:root` and `web/src/index.css`
  — same `--accent:#4f46e5`, same light/dark severity palette. This is an evolution of the
  existing system, not a new one. Reuse the app's existing tokens; do not reintroduce hex.
- **Honesty guardrails hold** (see repo CLAUDE.md): KPI deltas read "no prior run — no delta"
  when there is no basis; MITRE panel says "derived tags — not verdicts"; the AI Analyst shows
  an honest not-reachable state until Ollama is connected. Never fabricate numbers to fill the
  polished layout — the real-data screenshots show exactly how sparse-but-honest should look.

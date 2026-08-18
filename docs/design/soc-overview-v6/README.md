# SOC Overview — v6 design reference

New design drop from the user (2026-08-18). This is the **canonical visual spec for the
React Overview page** and the shared app shell. Plug it into `web/` — do NOT ship the raw
files; they are a reference to port to React + Tailwind.

## Files
- `SOC-Dashboard-v6.dc.html` — the design (latest of v2–v6). Open in a browser with
  `support.js` alongside to render it. It is an AI design-canvas export, so it contains
  a few non-standard bits to translate, not copy verbatim:
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

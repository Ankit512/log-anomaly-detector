# itsoc web — React SOC platform

Vite + React 18 + TypeScript frontend for the log-analyzer console. It is a
pure consumer of the existing Python backend (`console/serve.py`); it never
computes a severity or verdict itself.

## Run (development)

```bash
# 1. backend — serves the API (and the legacy console) on 127.0.0.1:8765
python3 console/serve.py --no-open

# 2. frontend
cd web
npm install         # once; needs network. Everything runs offline afterwards.
npm run dev         # http://localhost:5173 — /api/* proxies to :8765
```

## Test / build

```bash
npm test            # vitest + testing-library (jsdom, no backend needed)
npm run build       # typecheck + production bundle in web/dist
```

Serving `web/dist` from `serve.py` is a later phase; use `npm run dev` for now.

## Stack

React 18 · TypeScript · Vite · Tailwind (class-strategy dark mode) ·
shadcn-style components (Radix Slot, CVA) · TanStack Query (server state) ·
TanStack Table + Virtual (Alerts) · Zustand (UI state) · Visx (charts) ·
React Router. No CDN at runtime; all assets are local after `npm install`.

## Layout

- `src/components/layout/AppShell.tsx` — THE uniform shell (sidebar, topbar,
  theme toggle); every route renders inside it.
- `src/pages/` — Overview, Alerts, Incidents, Threat Intel, Assets, Reports,
  Cases and Settings are all live against real backend endpoints (contract in
  `docs/soc_subsystems.md`); each shows real data or an honest empty state.
- `src/lib/api.ts` — the typed client for the real endpoints only.
- `src/index.css` — all design tokens (light + dark, incl. the validated
  severity palettes) defined once.

## Honesty rules carried over from the console

Deltas render only when the backend provides a prior period; empty data says
so instead of drawing charts; the AI analyst is advisory-only; unbuilt nav
items say "soon" and link nowhere; no operational metrics are invented.

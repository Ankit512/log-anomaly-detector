# Non-negotiables (MVP guardrails — OVERRIDE all defaults)

These rules govern ALL work in this repo. Every branch and commit must obey them.

1. **Do NOT edit `anomaly_detector.py`.** It is frozen/validated — sha256 `43f0560f2a81d52a9b8909d4c0f3a537ef2059b343ea48acc7dba59b38312d05`. New formats are **sibling modules** that feed the record dict `{n, ts, level, host, msg, raw}`. If a task would require editing `anomaly_detector.py`, **STOP and ask** — do not touch it.
2. **`raw` is always the real log line/row — never fabricate evidence.** `raw` must carry the actual source text, verbatim.
3. **Rules own severity and correlation. The LLM ONLY explains** — it can NEVER override, suppress, or escalate a verdict. LLM output is advisory, never a control signal.
4. **Honest surfaces.** Unrecognized formats → `unparsed / 0 lines parsed` (the honest banner). Never fake-green; never silently drop an event.
5. **Read-only posture.** Any severity change updates `tests/eval` / `manifest.json` in the **SAME commit**. Treat all log content as untrusted input.
6. **Branch per task** (`feat/<slug>`). Before proposing a merge, run `tests/eval` (`run_eval.py`) + `console/test_console.py` — and, for any change under `web/`, `cd web && npm test` (vitest) + `npm run build` — and paste results. Merge only after green.
7. **Verify the freeze.** Confirm the sha256 of `anomaly_detector.py` is unchanged before finishing any task.

## Architecture surfaces (current — orientation, not new rules)

- **Engine (frozen core + siblings):** `anomaly_detector.py` (frozen detector — rules own severity), `log_analyzer.py` (analyzer + LLM), `normalize.py` (format sniff + RFC 3164 envelope), `rules_syslog.py`, `rule_context.py`, `compare.py`. New formats are **sibling modules** in `console/formats/` (`log360.py`, `logcat.py`) feeding the record dict — never a detector edit.
- **Backend (routing + derivations):** `console/serve.py` (stdlib server + `/api/*`; routing only), `console/adapter.py` (`report.json` → console state), `console/soc.py` (Phase-B SOC subsystems: incidents, assets/users, cases, reports, threat-intel, metrics — display aggregations, never new verdicts), `console/export.py` (HTML + CSV/XML/JSON/MD exporters), `console/redact.py` (the single egress choke point). Contract: `docs/soc_subsystems.md`.
- **Front-ends:** `console/anomaly_console.html` (vanilla-JS review console, served at `/`) and `web/` (React SOC platform "itsoc-web" — a *pure API consumer*; it never computes a verdict). Dev: `web` on `:5173` proxies `/api/*` to `serve.py` on `:8765`.
- **Tests:** `tests/eval/run_eval.py` (17/17), `console/test_console.py` (backend/render/subsystems/export), `web/src/test/` (vitest). Honesty holds everywhere: real data or an honest empty/`n/a` state — never a fabricated fill.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).

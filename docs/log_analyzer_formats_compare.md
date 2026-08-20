# Unrecognized-input handling — MODE A (honest) vs MODE B (force): a comparison

The broadened multi-format ingestion (JSON / JSONL / CSV / XML / HTML / Windows
text export / EVTX auto-detect + encoding detection) is landed in
`formats_universal.py`, native-first (the existing `normalize.py` still parses
the formats it already knows), feeding the **frozen** detector unchanged
(`anomaly_detector.py`, sha256 `43f0560f…312d05`).

The one open design question — **what to do with a genuinely-unrecognized
input** — is implemented **behind a switch** so you can see both behaviours and
choose. Pick with `--unrecognized-mode {honest,force}` or the
`LOG_ANALYZER_UNRECOGNIZED_MODE` env var. Default today is **honest** (the repo
guardrail); nothing is merged.

- **MODE A — honest-unrecognized (repo guardrail).** If the native parser
  recognizes nothing *and* the content is not a structured format we can parse,
  the report says **"FORMAT NOT RECOGNIZED — NOT an all-clear"**, 0 lines parsed,
  and the detector is fed **no** synthetic records.
- **MODE B — force-parse (the downloaded file's philosophy).** The same input is
  parsed as generic text and the detector runs over it. The old crash is fixed:
  universal records are adapted to the detector's `{n, ts, level, host, msg,
  raw}` contract, so `detect()` never raises, and severity is **never fabricated**
  (it defaults to INFO when the source gives none — no keyword-guessing).

Two things are **not** a mode choice and are fixed unconditionally:

1. **Empty input** always writes the honest `EMPTY INPUT — NOT an all-clear`
   report (the earlier build's early `return 2` broke `scripts/intake.py`; that
   is gone).
2. **Structured inputs** (JSON/JSONL/CSV/XML/HTML/Windows-text/EVTX) are parsed
   the **same way in both modes** — they are *recognized*, not "unrecognized",
   so the switch does not touch them.

## Side-by-side (produced by the local, network-free intake flow, rules-only)

| sample | mode | linesParsed | unrecognized | emptyInput | findings | detector rule (severity) | honest banner shown to the analyst |
|---|---|---|---|---|---|---|---|
| **unrecognized** (mac console text, 11 lines) | **A honest** | **0** | **True** | False | 0 | — | **FORMAT NOT RECOGNIZED … NOT an all-clear** |
| **unrecognized** (mac console text, 11 lines) | **B force** | **11** | **False** | False | 0 | — | *(normal report — 0 findings, no banner: looks like a clean bill of health)* |
| empty file (0 bytes) | A honest | 0 | False | **True** | 0 | — | EMPTY INPUT … NOT an all-clear |
| empty file (0 bytes) | B force | 0 | False | **True** | 0 | — | EMPTY INPUT … NOT an all-clear |
| structured JSON (7 events) | A honest | 7 | False | False | 1 | `auth_bruteforce` (**high**) | *(normal report — finding shown)* |
| structured JSON (7 events) | B force | 7 | False | False | 1 | `auth_bruteforce` (**high**) | *(normal report — finding shown)* |
| structured CSV (7 rows) | A honest | 7 | False | False | 1 | `error_rate_spike` (**medium**) | *(normal report — finding shown)* |
| structured CSV (7 rows) | B force | 7 | False | False | 1 | `error_rate_spike` (**medium**) | *(normal report — finding shown)* |

**Neither mode crashes** on any sample (the reported `detect()` crash is fixed by
the record adapter).

## What the difference actually is

The **only** row that differs between the two modes is the genuinely-unrecognized
file:

- **MODE A** tells the analyst the truth: *"I could not read this format — do not
  treat 0 findings as safe."* This is the current guardrail and what the
  `test_intake` / console `unrecognized -> precision n/a` tests assert.
- **MODE B** parses the 11 lines as text and shows a **normal report with 0
  findings and no banner** — which, for a file the tool could not really
  interpret, *reads as a clean bill of health*. It will, however, surface
  findings in unrecognized-but-text logs that happen to contain patterns the
  rules match (its upside: nothing readable is ever refused).

The structured-format rows show the payoff that lands **regardless** of which
mode you pick: JSON and CSV are now parsed, and the frozen rules fire on the
**source-reported** data — e.g. the CSV's `error_rate_spike` comes from five rows
whose `level` column literally says `ERROR` (severity read from the source, never
guessed from the message text).

## The honesty properties hold in both modes

- Detector frozen; `raw` is the verbatim source line/record.
- Severity is source-reported (`level`/`Level`/`severity`/`priority` fields),
  defaulting to INFO — no keyword-guessing from message text, in either mode.
- MODE A keeps the honest 0-parsed/unrecognized state; MODE B never fabricates a
  severity or a finding — it just declines to call an unreadable file
  "unrecognized".

## How to reproduce

```bash
# honest (default)
python3 log_analyzer.py --input tests/eval/cases/neg_unrecognized_format.log \
  --output /tmp/r --rules-only
# force
python3 log_analyzer.py --input tests/eval/cases/neg_unrecognized_format.log \
  --output /tmp/r --rules-only --unrecognized-mode force
```

Automated coverage: `console/test_console.py` → `check_formats_universal` (JSON +
CSV happy-path with source-reported severity; unrecognized honest-vs-force with
no crash; empty stays honest in both modes).

**No default is chosen here and nothing is merged — this is for you to pick.**
Tell god which mode to finalize.

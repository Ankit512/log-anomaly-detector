# AI Log Analysis & Anomaly Detection — Project Handoff

> Purpose: a self-contained summary so this work can be continued in a new session
> without losing context. Covers the goal, what's been built, the architecture, how to
> run it, known issues, and what's next.

_Last updated: 2026-08-16 · Repo: `~/Projects/log-analyzer` · GitHub: `Ankit512/log-anomaly-detector` (public, CI green)_

---

## 1. Goal & context

Building the first stages of a larger **AI Operations Platform for DC / NOC / SOC**. Full vision:

```
Agent → Agentic Skills → MCP → API/Security Gateway → Certificate/Token → Infrastructure
```

with a mandatory security principle: **API-first + certificate/token auth, no
username/password integration, human approval before any write action.**

We started at the bottom-left — **log analysis** — and have now completed **anomaly
detection** with real-format support and a regression test harness. Everything else
(live input, MCP enrichment, RCA, gated remediation) is Stage C, not yet started.

### Hard requirements / decisions (unchanged)
- **Open-source models only** (Llama / Mistral / Qwen); avoid Claude/Anthropic in the runtime.
- **Run locally via Ollama** (`llama3.1:8b`) so log data never leaves the machine.
- **No training / fine-tuning** — in-context reasoning + deterministic rules.
- **Chunk logs** (~100 lines) rather than relying on a huge context window.
- **Read-only.** No live system access, no remediation. Earn trust first.

### Hardware
MacBook Air M4, 16GB RAM. Target a 7B–8B model at Q4/Q5. Do not attempt 70B locally.

---

## 2. Current status

| Stage | Description | Status |
|-------|-------------|--------|
| **A** | Log triage on a local open-source model | ✅ Done |
| **B** | Anomaly detection (deterministic + LLM), real-format support, eval harness | ✅ Done & regression-guarded |
| **C** | Ops platform (live input, MCP tools, RCA, gated remediation) | 🟡 T9 threat-intel enrichment prototype landed; rest not started |
| **UI** | Local review console + `serve.py`, log-source picker, run history, standalone export | ✅ Built, live, CI-tested (visuals unverified in-browser) |

**What works today:** the full detect-and-explain loop runs locally on real RFC 3164
syslog (sshd/PAM) and the original canonical format. Deterministic rules own severity and
correlation; the LLM explains findings and fills gaps below rule thresholds. Findings name
attacking IPs with accurate, de-duplicated attempt counts. A labeled evaluation corpus
guards every fix against regression.

**What's blocked:** real-world accuracy validation and environment-specific tuning both
need production logs, which are not currently available.

---

## 3. Architecture

Two layers, deliberately separated:

- **Detector** (`anomaly_detector.py`) — the validated original. A pure function
  `detect(records)` applying windowed rules: brute-force (≥5 real attempts/IP within a
  sliding 120s window), failure→success compromise, error-burst, suspicious-port, disk.
  Rules are **authoritative on severity**. Kept effectively frozen (see §4 for the one
  bounded edit); the pristine import is preserved in `archive/anomaly_detector_original.py`.
- **Analyzer** (`log_analyzer.py`) — chunks the log, runs the detector first, and feeds the
  pre-flagged anomalies to the LLM as authoritative context so the model **explains** rather
  than guesses severity. Anything below a rule's threshold (e.g. disk at 78%) is the model's
  to catch.

**The key design unlock (T5):** the reuse seam is the **record dict**
(`{n, ts, level, host, msg, raw}`), not a typed-event API. Real formats are supported by
converting them into that record shape:

```
raw log → normalize.py (envelope)  → rules_syslog.py (vocabulary) → anomaly_detector.detect() → LLM
          timestamp/host/level        real sshd/PAM phrasing →         (unchanged)
          year inference, WARN         the frozen regexes' wording
```

- **Envelope vs vocabulary are separate files** because they evolve at different rates
  (new sources touch the envelope; new phrasings touch the vocabulary).
- **`raw` is always the real log line.** Matching runs against canonicalized `msg`, but
  evidence shown to a human is the true line — honest, not a rewrite.
- New formats become **new sibling modules**, not edits to the validated core.

---

## 4. What was built (commit by commit)

Feature commits, in order:

| Commit | Milestone | What shipped |
|--------|-----------|--------------|
| `fe696d8` | T1 | Endpoint-agnostic analyzer: OpenAI-compatible `/v1/chat/completions`, env config (`LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL`), deterministic default (`LLM_TEMPERATURE=0`), configurable chunk size (`--lines-per-chunk` CLI flag, default 100). Ollama local by default; Anthropic original archived. |
| `ef3ddf1` | T3 | Detector→analyzer integration. Detector runs in-process before the LLM; anomalies authoritative; retry-safe context via a shared `build_user_prompt` (closes the retry-path blind spot); in-analyzer dedupe; timestamp-based restatement matcher. 5/5 validation. |
| `05bf5b7` | T5 | Real syslog: `normalize.py` (RFC 3164 envelope, year inference w/ Dec→Jan rollover, proc/pid) + `rules_syslog.py` (sshd/PAM vocabulary → frozen regexes; POSSIBLE BREAK-IN sibling rule). Reuses `detect()` over the record dict; detector byte-identical; `raw` preserved. |
| `1585b1a` | T5a | Schema-drift fix: `validate_response()` checks top-level **and** item-level shape, retries on mismatch, emits a loud `analyzer_error` instead of a silent all-clear. Markdown-writer crash hardened. Auth-failure level → WARN to cut error-rate-spike noise. |
| `f8825f4` | T4 | Sliding-window brute-force severity replaces whole-file span (fixes sustained-attack under-rating). **The one bounded edit to the detector** — pristine original archived; sha baseline reset. |
| `867bcb6` | T4 | Username-spray enrichment: findings report distinct-username count at merge time (derived in the analyzer, detector untouched). |
| `21c96f0` | T4 | Variant A auth dedupe in `rules_syslog.dedupe_auth_attempts()`: one event per real attempt (OpenSSH 1122→524 events); entities carry true attempt counts; FP anchors all preserved. |
| `cc86b93` | T6 | Labeled eval corpus (`tests/eval/`) + `run_eval.py` scoring harness. 15/15 pass; mutation-tested to prove it can fail; non-zero exit = CI-ready. |
| `9d92674` | T9 (Stage C) | Threat-intel enrichment prototype in `threat_intel/` (branch `stage-c-threat-intel`). Matches the analyzer's flagged IPs against STIX/TAXII indicators → MITRE ATT&CK techniques. Offline-first (stdlib-only), downstream of the analyzer, core untouched. Import guard + `export_iocs.py` + demo + network-free smoke test. |
| `79880dd` | UI | Self-contained vanilla-JS **review console** (`console/anomaly_console.html`), ported from a Nocturne design export — no build step, no framework, no network (dropped the Google-Fonts import). |
| `677affb` | UI/audit | `rule_context.py`: emits a readable **rule predicate** (from the detector's live constants, so it can't drift) + an **event timeline** per finding. Deterministic, no model call. |
| `d3dc4fd` | Compare | Opt-in `--compare` **LLM-alone ablation**: a second *unprimed* pass records what the model rates each finding on its own → `llm_alone_severity` / `llm_alone_delta` / `compare.underrated_count`. Additive, default OFF, authoritative severities unchanged. Results cached; degraded chunks reported UNKNOWN (never counted as under-rated). |
| `9c706db` | UI | **Log-source picker** — `serve.py` runs with no `--input` and offers three sources: bundled samples, a local file (multipart upload, read locally), and fetch-from-URL (the only networked source; downloads public test data). `--input` still works as a shortcut. |
| `914fee9` | Honesty | 0-parsed input **skips the LLM entirely** and shows an "unrecognized format" state independent of finding count. Measured on a macOS log: 21 spurious model findings → 0. |
| `18a24d6` | Perf | LLM scoped to **chunks containing findings** (OpenSSH_2k: 80 chunks → 22), per-chunk context (87% smaller prompts), async `/api/analyze` (202 + progress polling), rules-only results published in ~8s. |
| `89f41a8` `9466352` `6f0df1b` | Perf | Ollama `keep_alive` pinned; **lazy explanations** (eager top-3, rest on demand via `/api/explain`); explanations tied to the specific finding they describe, never pasted across same-type findings. Diagnosis: warm call ≈14s; the earlier 72–131s was model reload + swap on a 16GB machine. |
| `9653e83` | UI | **Run history + navigation pane** — completed runs persist to `console/.runs/`; a restart restores the last run; the Runs button reopens any of the last 25. |
| `12998bb` | Docs | **`RUNBOOK.md` + `RUNBOOK.pdf`** — beginner-friendly, covers every use case. PDF generated by a stdlib-only writer (macOS 15 dropped the cups html/rtf filters). |
| `5f71a90` | UI | **Standalone HTML export** (`console/export.py`, "Download standalone") — one self-contained file, opens anywhere with **zero network requests**, no install. |
| `ac2e7db` | UI wiring | `console/serve.py` + `console/adapter.py`: one command runs the analyzer, adapts `report.json` → console state, and serves the reviewed run at `127.0.0.1`. `report.json` made **self-describing** (input + detector sha256, parsed/unparsed counts, ruleset). Integrity manifest (recomputable hashes, **not** a signature); target host derived from the log line; honest compare-not-run / partial / all-clear states. |

**Detector integrity:** current `anomaly_detector.py` sha256 `43f0560f…8312d05` (after the
one sliding-window edit). Pristine import `d1b2ae80…b96d936` in `archive/`. All UI, compare,
and threat-intel work is **additive** — the detector stays byte-identical through every commit
above.

---

## 5. Files in the project

| File | What it is |
|------|------------|
| `log_analyzer.py` | Analyzer: format sniff → parser → `detect()` → LLM; schema validation, dedupe/restatement, username enrichment, JSON+MD report. |
| `anomaly_detector.py` | Validated detector (v1). One bounded edit (sliding-window severity). Rules own severity. |
| `normalize.py` | RFC 3164 envelope parsing: timestamp/host/proc-pid, year inference, level synthesis (`LEVEL_HINTS`, auth→WARN). |
| `rules_syslog.py` | Vocabulary canonicalization (sshd/PAM → frozen phrasing), `possible_break_in` sibling rule, `dedupe_auth_attempts()`. |
| `rule_context.py` | Emits the readable rule predicate (from live detector constants) + event timeline per finding. Deterministic. |
| `compare.py` | Opt-in `--compare` LLM-alone ablation → `llm_alone_severity`/`_delta` + `compare.underrated_count`. Additive; cache is gitignored. |
| `console/` | The app: `serve.py` (stdlib local server, picker, run history, port reclaim), `adapter.py` (`report.json` → console state), `anomaly_console.html` (vanilla-JS review console), `export.py` (standalone HTML export), `test_console.py` (render + routing tests, 130 checks). |
| `RUNBOOK.md` / `.pdf` | Step-by-step guide for a first-time, non-technical user. Covers all use cases, troubleshooting, timings, limits. |
| `tests/eval/` | Labeled corpus (`manifest.json` + `.log` fixtures) and `run_eval.py` scoring harness. |
| `archive/` | `anomaly_detector_original.py` (pristine reference), `log_analyzer.py.anthropic.bak`. |
| `samples/` | Real LogHub datasets: `Linux_2k.log`, `OpenSSH_2k.log`. |
| `sample-2.log` | 19-line synthetic baseline (canonical format, 3 planted issues). |
| `threat_intel/` | Stage C (T9) prototype: `threat_detector.py` (match IOCs→MITRE ATT&CK), `taxii_client.py` (STIX/TAXII, import-guarded), `mitre_attack.py` (ATT&CK mapper), `export_iocs.py` (report.json→IOC list), `demo_threat_intel.json`, `test_threat_intel.py`, `requirements-taxii.txt` (live-mode deps only), `README.md`. Offline mode is stdlib-only. |
| `.env.example`, `.gitignore`, `README.md` | Setup. Copy `.env.example` → `.env`; local Ollama needs no real key. |

### How to run
```bash
# LLM triage + integrated detection (canonical or syslog)
python3 log_analyzer.py --input samples/OpenSSH_2k.log --output report
# -> report.json, report.md

# Deterministic detector only (no model)
python3 anomaly_detector.py --input samples/OpenSSH_2k.log --output anomalies

# Review console (the app): one command → reviewed run at http://127.0.0.1:8765/
python3 console/serve.py                       # picker: bundled / local file / URL
python3 console/serve.py --input sample-2.log --compare
#   --compare  = also run the LLM-alone ablation (opt-in, doubles inference)
#   --report report.json      = review an existing report instead of re-analyzing
#   --threat-intel <report>   = merge MITRE/threat-intel chips

# Share a run with someone who has nothing installed (one self-contained file)
python3 console/export.py report.json -o run.html      # or --latest

# Tests (all run headless, no network, no model — CI-guarded)
python3 tests/eval/run_eval.py            # 15/15 expected
python3 threat_intel/test_threat_intel.py
python3 console/test_console.py           # console render smoke test
```

### Configuration
- **Env (`.env`, 4 keys):** `LLM_BASE_URL` (default `http://localhost:11434/v1`),
  `LLM_API_KEY` (`ollama`), `LLM_MODEL` (`llama3.1:8b`), `LLM_TEMPERATURE` (default `0`).
- **Chunk size:** CLI flag `--lines-per-chunk` (default 100) on `log_analyzer.py` — not an env var.
- **Detector constants:** `BRUTE_FORCE_MIN_FAILURES` (5), `BRUTE_FORCE_WINDOW_SEC` (120),
  `COMPROMISE_SUCCESS_WINDOW_SEC` (120), `ERROR_BURST_MIN` (5), `ERROR_BURST_WINDOW_SEC` (60),
  `DISK_WARN_PCT` (80), `DISK_CRIT_PCT` (90), `SUSPICIOUS_PORTS`.
- **`normalize.py` `LEVEL_HINTS`:** maps synthesized levels (auth failures → WARN).

---

## 6. Known issues / tech debt

- **Disk severity is a parked product decision.** Current: ≥90% → high, 80–89% → medium.
  Arguably ≥90% should be critical. Changing it edits the detector and shifts every report —
  and now also requires updating `tests/eval/manifest.json` in the same commit (by design).
- **`possible_break_in` = medium** (arguably high). Documented; a reverse-DNS mismatch is a
  lower-confidence signal, so medium was chosen to avoid severity inflation.
- **Auth dedupe is a heuristic** (Variant A: drop IU/PAM lines when their PID has a
  Failed-password anchor). PAM-only logs (e.g. `Linux_2k`) have no anchors, so they are not
  deduped — intentional bias toward under-deduping over suppressing real attempts.
- **Small-model drift.** `llama3.1:8b` abandons the JSON schema on dense 100-line chunks. It
  now **fails loudly** (`analyzer_error`), not silently. Mitigate with a smaller
  `--lines-per-chunk` or a larger model.
- **LLM explanation coverage.** The model occasionally skips a `rule_id` (renders `n/a`).
  Optional fix: a second pass for missing ids.
- **Eval baseline caveat.** 15/15 / precision 1.000 means "unchanged vs known behaviour," not
  "correct in the wild." Its value is the next regression it catches; true accuracy needs
  production logs.
- **Compare-mode headline is ~21%, not a landslide.** A six-input benchmark at 25-line chunks
  (`benchmark_compare.md`, uncommitted) measured 3 of 14 comparable findings under-rated, with
  the model *over*-rating 4 — and 2 of the 3 under-rated cases come from the synthetic
  `sample-2.log`. On real syslog it is 1 of 10. The defensible claim is narrower than a
  percentage: **the rules catch correlation the model doesn't** (failure→success compromise,
  blocked-but-suspicious egress). Chunk size was the other finding: 0 of 21 chunks degraded at
  25 lines vs 100% at 100 lines.
- **Explanations are partial by design on large logs.** Only the top-3 findings are explained
  eagerly; the rest are generated on demand when opened (~14s each). Anything deterministic —
  severity, evidence, rule predicate, timeline — is always complete.
- **Not persisted:** analyst marks, and on-demand explanations generated after a run is
  reopened from history.

---

## 7. Next steps

**Presentation layer — BUILT (beyond the original A/B/C roadmap)**
- Review console + `serve.py` are live: one command from a log to a browser-reviewed run,
  fully local. `--compare` shows the RULE-vs-LLM-alone contrast. CI runs the eval, threat-intel,
  and console tests headless on every push.
- Remaining on the console: eyeball the rendered visuals + severity colour contrast on the dark
  theme (verified numerically — hue/contrast — but never seen in a browser in-session).
- Persist analyst marks and on-demand explanations back into run history.
- More formats (RFC 5424, JSON logs, vendor exports); each is a sibling module, not a detector
  edit. A macOS unified log currently reports "format not recognized" — correctly, but it is
  the obvious next parser.

**Finish Stage B (demand-driven)**
- **Real-log validation** on production logs for true FP/FN — blocked on data availability.
- **Remaining formats (T5):** RFC 5424, JSON logs, vendor exports (Check Point / Aruba /
  Log360), multi-line stack traces; plus a structured line-range field so detector context
  can be scoped per chunk on large multi-chunk logs.
- **Deferred T4 tuning:** thresholds + `SUSPICIOUS_PORTS` to the real environment; the disk
  severity decision; optional LLM explanation second pass.

**Stage C (only once there's a real environment / need)**
- **T7 Live input** — tailed file / stream / SIEM API pull for continuous operation.
- **T8 Analyst feedback loop** — capture true/false-positive marks; refine rules + few-shot.
- **T9 Read-only enrichment** — threat-intel matching + MITRE ATT&CK prototype is IN
  (`threat_intel/`, offline-first). Remaining: fix `severity_for()` (flattens every match
  to CRITICAL); wire live TAXII **and** replace its `--taxii-password` with certificate/token
  auth before enabling it (current CLI-password path violates the security principle); add
  CMDB asset-criticality and past-incident-history sources; tighten the permissive `DOMAIN_RE`;
  make the ATT&CK cache auto-refresh. Offline stays the default (no log egress).
- **T10 RCA + incident records** — correlate findings into root-cause narratives.
- **T11 Gated remediation (last)** — human-approved actions above a severity threshold, with
  a mandatory verify step; certificate/token via the API/security gateway, never
  username/password.

---

## 8. Design constraints (held throughout)

Data stays local (Ollama) · no model training · read-only, no automated actions · human
approval before any future write · certificate/token auth only · secrets never in prompts,
code, `.env`, or logs sent to any model.

---

## 9. Quick prompt to resume

> "Continuing my local AI log-analysis project (`~/Projects/log-analyzer`). Read
> PROJECT_HANDOFF.md. Stage A + B are done: the A+B detect-and-explain loop runs locally via
> Ollama on real syslog, with correct de-duplicated severities and a `tests/eval/` regression
> harness (15/15). The detector is frozen except one sliding-window edit; pristine copy in
> `archive/`. Next I want to [e.g. add JSON/RFC 5424 parsing / wire the eval into CI / start
> Stage C read-only MCP enrichment / validate on my real logs]. No Claude in the runtime, no
> training, read-only."

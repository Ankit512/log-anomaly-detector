# AI Log Analysis & Anomaly Detection

A local, read-only tool that reads server and security logs, flags anomalies with
deterministic rules, and uses a local LLM to explain them in plain language. **Log data never
leaves your machine.**

Deterministic rules own severity and correlation (brute-force, failure→success compromise,
error bursts, suspicious ports, disk pressure); the LLM only explains rule-caught findings and
surfaces anything below a rule's threshold — it can never override, suppress, or escalate a
verdict. On top of the detector sits a full **SOC platform**: a browser dashboard with
Overview, Alerts, Incidents, Threat Intel, Assets, Reports and Cases — every panel showing
real derived data or an honest empty state, never a fabricated number.

Recognized log formats: the canonical `timestamp LEVEL host msg`, real **RFC 3164 syslog**
(sshd/PAM), **ManageEngine Log360** exports (CSV + forwarded syslog), and **Android logcat**.
Unknown formats surface an honest *"format not recognized — 0 lines parsed"* banner, never a
false all-clear.

> **Never used it before?** [`RUNBOOK.md`](RUNBOOK.md) (also as [PDF](RUNBOOK.pdf)) walks
> through every use case step by step, for non-technical users.
> [`GUIDE.md`](GUIDE.md) is a plain-language overview.
> [`PROJECT_HANDOFF.md`](PROJECT_HANDOFF.md) has architecture, history and roadmap.
> [`docs/soc_subsystems.md`](docs/soc_subsystems.md) is the SOC data-model + API contract.
> [`CLAUDE.md`](CLAUDE.md) holds the repo's non-negotiable guardrails (detector frozen, rules
> own severity, honest surfaces) for anyone — human or agent — working in the code.

Runs on **macOS, Linux and Windows**. Python standard library only — no `pip install`, and
**no Node needed to run**: the React dashboard ships as a pre-built bundle that `serve.py`
serves at `:8765`. (Node is only needed if you want to *modify* the frontend. The `mcp` SDK is
only for the optional read-only MCP server in [§6](#6-mcp-server-optional) — the core needs no
`pip install`.)

---

## 1. Install

### Step 1 — Python 3.9+

| | Check | If missing |
|---|---|---|
| **macOS** | `python3 --version` | Preinstalled; or `brew install python` |
| **Linux** | `python3 --version` | `sudo apt install python3` (Debian/Ubuntu) |
| **Windows** | `python --version` | [python.org/downloads](https://www.python.org/downloads/) — tick **"Add Python to PATH"** |

> On Windows, use `python` wherever this README says `python3`.

### Step 2 — Ollama (runs the AI locally)

Download from **<https://ollama.com/download>** — installers for macOS, Windows and Linux.
Linux one-liner:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Then pull the model (~5 GB, once) and confirm:

```bash
ollama pull llama3.1:8b
ollama list
```

Ollama runs as a background service after install. If the tool later says it cannot reach
the endpoint, start it manually with `ollama serve`. The rules engine still runs **without**
a model — you just get verdicts and evidence, with explanations skipped and said so honestly.

### Step 3 — this project

```bash
cd log-analyzer
cp .env.example .env          # macOS / Linux
copy .env.example .env        # Windows (cmd)
```

No editing needed for local use: the placeholder API key is deliberate, because a local
model does not need a real one.

**Hardware:** an 8B model needs roughly 8 GB of free RAM. On 16 GB total, close other
large apps — swapping is the single biggest cause of slow runs.

---

## 2. Quick start

```bash
python3 console/serve.py
```

A browser opens at **http://127.0.0.1:8765/** showing the **React SOC dashboard** — one
command, one URL, **no Node required**: the app is served from a production build committed to
the repo (`web/dist`). Upload a log (or pick a bundled sample) and you are running.

To stop it: `Ctrl-C` in the terminal.

---

## 3. The SOC dashboard, and how it's served

`console/serve.py` is the single local backend (stdlib HTTP, `127.0.0.1:8765`) — it owns
analysis, saved runs, and a JSON API. It **also serves the built React SOC platform**
(`web/`, "itsoc-web") at `/`, so `python3 console/serve.py` alone shows the dashboard with no
Node install. The React app is a *pure consumer* of the API; it never computes a verdict
itself. The older vanilla review console stays reachable at
[`/legacy/overview.html`](http://127.0.0.1:8765/legacy/overview.html) and
[`/legacy/alerts`](http://127.0.0.1:8765/legacy/alerts).

### Developing the frontend (optional)

Only needed if you're changing the React code. The Vite dev server gives hot-reload; the
backend still serves the API on `:8765`:

```bash
python3 console/serve.py --no-open      # API on :8765
cd web && npm install && npm run dev    # http://localhost:5173 — /api/* proxies to :8765
```

After changing the frontend, rebuild and commit the bundle so the one-command flow stays
current:

```bash
cd web && npm run build                 # regenerates web/dist (committed to the repo)
```

The dashboard's sections, each backed by a real endpoint (contract in
[`docs/soc_subsystems.md`](docs/soc_subsystems.md)):

| Section | What it shows | Endpoint |
|---|---|---|
| **Overview** | KPI tiles, severity donut, alerts-over-time, top MITRE tactics, latest alerts | `/api/overview`, `/api/metrics` |
| **Alerts** | Every finding, filterable/sortable, with the full evidence detail | `/console_state.json` |
| **Incidents** | Correlated finding-clusters with an analyst lifecycle (`new → acknowledged → investigating → resolved`) | `/api/incidents` (+ `POST /state`) |
| **Threat Intel** | Offline STIX indicators + each rule's MITRE technique map | `/api/threat-intel` |
| **Assets** | Hosts/IPs and users **actually observed** in the run, with per-entity findings | `/api/assets`, `/api/users` |
| **Reports** | Saved HTML reports, one-click generate, and **downloadable exports** (below) | `/api/reports`, `/api/export` |
| **Cases** | Analyst-created case records (CRUD) | `/api/cases` |

Everything is honest by construction: incident/asset severities are display roll-ups (rules
still own the verdict), MITRE tags are labelled *derived, not a verdict*, and any value with
no basis renders *n/a* rather than a zero that looks like good news.

---

## 4. Analyze a log

```bash
python3 console/serve.py                                   # pick a log in the browser
python3 console/serve.py --input samples/OpenSSH_2k.log    # analyze immediately
python3 console/serve.py --input sample-2.log --compare    # + LLM-alone comparison
python3 console/serve.py --report report.json              # reopen an existing report
python3 console/serve.py --port 8766                       # different port
```

**Three log sources**, deliberately separated because their privacy consequences differ:
bundled samples, a **local file** (read locally, never uploaded), and **fetch from a URL**
(the only source that uses the network — it *downloads* public test data to you). The Upload
button in the dashboard offers the same choice (local file **or** a link).

**Results survive a restart.** Completed runs are saved locally; the **Runs** switcher reopens
any of them, and restarting the app restores the last one.

**Compare mode (`--compare`, opt-in)** runs a second *unprimed* pass — same model, same log,
rules removed — and shows RULE verdict vs LLM-alone side by side. Off by default: it doubles
inference time. Measured across six logs, the rules out-rated the model about **21%** of the
time, and the model out-rated the rules about as often.

---

## 5. Export & share a run

**One self-contained HTML file** — opens by double-clicking, anywhere, with **zero network
requests** (no Python, no Ollama, no server):

```bash
python3 console/export.py report.json -o run.html
python3 console/export.py --latest -o run.html
```

**Downloadable exports in five formats** from the Reports page (or directly):

```
GET /api/export?format=csv | html | xml | json | md
```

Each is a real serialization of the current run's findings — same ids, severities, MITRE tags
the rules produced, no fabricated rows. CSV/XML/JSON are machine-readable; HTML is the
interactive standalone page; Markdown is a readable summary table. With no run loaded the
endpoint returns an honest `409`, never an empty file.

---

## 6. MCP server (optional)

`itsoc_mcp/` is a **read-only** [MCP](https://modelcontextprotocol.io) server that exposes this
project's existing analysis to an MCP-capable agent (Claude Code / Desktop). It is honest and
local by design: it is a **client** of the running backend (`http://127.0.0.1:8765`) and
**computes no verdicts** — severity and correlation stay rule-owned by the frozen detector,
explanations are advisory, MITRE tags are derived. Raw log text is **redacted by default**
through the same `console/redact.py` choke point the rest of the project uses (raw only with
`ITSOC_MCP_TRUSTED_LOCAL=1`), and every response carries a provenance block with the detector
sha256. The seven tools are `analyze_log`, `list_runs`, `get_findings`, `get_evidence`,
`explain_finding`, `export_run`, and `threat_intel_lookup`.

The `mcp` SDK is the **only** extra dependency and it is for this optional server alone — the
core still runs with no `pip install`:

```bash
pip install -r itsoc_mcp/requirements-mcp.txt   # the mcp SDK only
python3 console/serve.py                         # the backend must be running
python -m itsoc_mcp                              # speak MCP over stdio (from the repo root)
```

See [`itsoc_mcp/README.md`](itsoc_mcp/README.md) for the full tool reference, the environment
variables, and a ready-to-paste MCP client registration JSON.

---

## 7. Command line

```bash
# Full analysis: rules + LLM explanations
python3 log_analyzer.py --input samples/OpenSSH_2k.log --output report
#   -> report.json (machine-readable), report.md (human-readable)

# Rules only — instant, no model required
python3 anomaly_detector.py --input samples/OpenSSH_2k.log --output anomalies

# Tests (no network, no model)
python3 tests/eval/run_eval.py             # 17/17 expected
python3 threat_intel/test_threat_intel.py
python3 console/test_console.py            # backend + render + subsystems + export
cd web && npm test                         # React dashboard (vitest, jsdom)
```

Useful flags: `--compare`, `--lines-per-chunk N` (default 25), `--deep-scan`, `--model`,
`--base-url`. Run any script with `--help` for the full list.

**Performance:** rules cover a 2,000-line log in under a second. The LLM is only asked about
chunks that contain findings, so cost scales with findings rather than file size — findings
appear in ~8 seconds and explanations fill in behind a progress bar.

---

## 8. Threat-intel enrichment (optional)

An opt-in downstream step in [`threat_intel/`](threat_intel/) matches flagged IPs against
threat-intel indicators and resolves each to a MITRE ATT&CK technique (a blocked outbound to
a known C2 IP → "T1071 — Command and Control"). Offline mode (a local STIX bundle) is the
default and needs no extra packages. See [`threat_intel/README.md`](threat_intel/README.md).

When the console is pointed at a remote compute node, **every byte that leaves the machine
passes through one redaction choke point** (`console/redact.py`) — the raw log is never
transmitted; only redacted finding-lines go out. Local mode remains the default (no egress).

---

## 9. Design constraints

Data stays local · no model training · read-only, no automated actions · **rules are
authoritative on severity; the LLM only explains** · the validated detector
(`anomaly_detector.py`) is kept effectively frozen (sha256 `43f0560f…8312d05`), with new
formats added as sibling modules · `raw` is always the real log line, never a rewrite · the UI
never claims more than it can prove (integrity hashes, not signatures; "compare not run", not a
fake zero; "format not recognized", not a false all-clear; *n/a*, not a guessed metric).

## 10. Project layout

Full inventory in §5 of [`PROJECT_HANDOFF.md`](PROJECT_HANDOFF.md). Key pieces:

- **Engine** — `log_analyzer.py` (analyzer + LLM), `anomaly_detector.py` (validated detector,
  frozen), `normalize.py` (format sniff + envelope), `rules_syslog.py` (vocabulary + dedupe),
  `rule_context.py` (rule predicate + timeline), `compare.py` (LLM-alone ablation).
- **Formats** — `console/formats/log360.py` (Log360 CSV + syslog), `console/formats/logcat.py`
  (Android logcat); each a sibling module feeding the record dict, never a detector edit.
- **Backend** — `console/serve.py` (stdlib server + JSON API), `console/adapter.py`
  (`report.json` → console state), `console/soc.py` (incidents, assets/users, cases, reports,
  threat-intel, metrics), `console/export.py` (HTML + CSV/XML/JSON/MD exporters),
  `console/redact.py` (egress choke point).
- **UIs** — `console/anomaly_console.html` (vanilla-JS review console), `web/` (React SOC
  platform).
- **Enrichment / tests / data** — `threat_intel/` (offline STIX → MITRE), `tests/eval/`
  (labeled corpus + harness), `console/test_console.py` (backend), `web/src/test/` (dashboard),
  `samples/` (real LogHub logs + Log360/Android samples).

---

## License

MIT — see [`LICENSE`](LICENSE).

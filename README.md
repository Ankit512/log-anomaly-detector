# AI Log Analysis & Anomaly Detection

A local, read-only tool that reads server and security logs, flags anomalies with
deterministic rules, and uses a local LLM to explain them in plain language. **Log data never
leaves your machine.**

Deterministic rules own severity and correlation (brute-force, failure→success compromise,
error bursts, suspicious ports, disk pressure); the LLM explains rule-caught findings and
surfaces anything below a rule's threshold. Supports the canonical `timestamp LEVEL host msg`
format and real RFC 3164 syslog (sshd/PAM).

> **Never used it before?** [`RUNBOOK.md`](RUNBOOK.md) (also as [PDF](RUNBOOK.pdf)) walks
> through every use case step by step, for non-technical users.
> [`GUIDE.md`](GUIDE.md) is a plain-language overview.
> [`PROJECT_HANDOFF.md`](PROJECT_HANDOFF.md) has architecture, history and roadmap.

Runs on **macOS, Linux and Windows**. Python standard library only — no `pip install`.

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
the endpoint, start it manually with `ollama serve`.

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

A browser opens at **http://127.0.0.1:8765/**. Choose a bundled sample and you are running.

To stop it: `Ctrl-C` in the terminal.

---

## 3. The review console

A self-contained local web app: findings ranked by severity, per-finding evidence, the rule
predicate that fired, an event timeline, and an integrity manifest. No build step, no
framework, no network.

```bash
python3 console/serve.py                                   # pick a log in the browser
python3 console/serve.py --input samples/OpenSSH_2k.log    # analyze immediately
python3 console/serve.py --input sample-2.log --compare    # + LLM-alone comparison
python3 console/serve.py --report report.json              # reopen an existing report
python3 console/serve.py --port 8766                       # different port
```

**Three log sources**, deliberately separated because their privacy consequences differ:
bundled samples, a **local file** (read locally, never uploaded), and **fetch from a URL**
(the only source that uses the network — it *downloads* public test data to you).

**Results survive a restart.** Completed runs are saved locally; the **Runs** button reopens
any of them, and restarting the app restores the last one.

**Compare mode (`--compare`, opt-in)** runs a second *unprimed* pass — same model, same log,
rules removed — and shows RULE verdict vs LLM-alone side by side. Off by default: it doubles
inference time. Measured across six logs, the rules out-rated the model about **21%** of the
time, and the model out-rated the rules about as often.

---

## 4. Share a run with someone who has nothing installed

```bash
python3 console/export.py report.json -o run.html
python3 console/export.py --latest -o run.html
```

Or click **Download standalone** in the console.

The result is **one HTML file** that opens by double-clicking, anywhere, with **zero network
requests** — no Python, no Ollama, no server. Findings, evidence, rule-vs-LLM contrast,
predicate, timeline and the integrity manifest are all inlined and still interactive
(filters, selection, keyboard).

---

## 5. Command line

```bash
# Full analysis: rules + LLM explanations
python3 log_analyzer.py --input samples/OpenSSH_2k.log --output report
#   -> report.json (machine-readable), report.md (human-readable)

# Rules only — instant, no model required
python3 anomaly_detector.py --input samples/OpenSSH_2k.log --output anomalies

# Tests (no network, no model)
python3 tests/eval/run_eval.py             # 17/17 expected
python3 threat_intel/test_threat_intel.py
python3 console/test_console.py
```

Useful flags: `--compare`, `--lines-per-chunk N` (default 25), `--deep-scan`, `--model`,
`--base-url`. Run any script with `--help` for the full list.

**Performance:** rules cover a 2,000-line log in under a second. The LLM is only asked about
chunks that contain findings, so cost scales with findings rather than file size — findings
appear in ~8 seconds and explanations fill in behind a progress bar.

---

## 6. Threat-intel enrichment (optional)

An opt-in downstream step in [`threat_intel/`](threat_intel/) matches flagged IPs against
threat-intel indicators and resolves each to a MITRE ATT&CK technique (a blocked outbound to
a known C2 IP → "T1071 — Command and Control"). Offline mode (a local STIX bundle) is the
default and needs no extra packages. See [`threat_intel/README.md`](threat_intel/README.md).

---

## 7. Design constraints

Data stays local · no model training · read-only, no automated actions · rules are
authoritative on severity · the validated detector (`anomaly_detector.py`) is kept effectively
frozen, with new formats added as sibling modules · the UI never claims more than it can
prove (integrity hashes, not signatures; "compare not run", not a fake zero; "format not
recognized", not a false all-clear).

## 8. Project layout

Full inventory in §5 of [`PROJECT_HANDOFF.md`](PROJECT_HANDOFF.md). Key pieces:
`log_analyzer.py` (analyzer + LLM), `anomaly_detector.py` (validated detector),
`normalize.py` (syslog envelope), `rules_syslog.py` (vocabulary + dedupe),
`rule_context.py` (rule predicate + timeline), `compare.py` (LLM-alone ablation),
`console/` (`serve.py`, `adapter.py`, `export.py`, the review console),
`threat_intel/` (enrichment), `tests/eval/` (labeled corpus + harness),
`samples/` (real LogHub logs).

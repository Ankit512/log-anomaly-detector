# AI Log Analysis & Anomaly Detection

A local, read-only tool that reads server and security logs, flags anomalies with
deterministic rules, and uses a local LLM to explain them in plain language. Log data never
leaves the machine.

Deterministic rules own severity and correlation (brute-force, failure→success compromise,
error bursts, suspicious ports, disk pressure); the LLM explains rule-caught findings and
surfaces anything below a rule's threshold. Supports the canonical `timestamp LEVEL host msg`
format and real RFC 3164 syslog (sshd/PAM).

> **New here?** Read [`PROJECT_HANDOFF.md`](PROJECT_HANDOFF.md) for the full architecture,
> build history, known issues, and roadmap.

## Requirements

- Python 3 (standard library only for the detector)
- [Ollama](https://ollama.com/download) running locally, with a model pulled:
  ```bash
  ollama pull llama3.1:8b
  ```

## Setup

```bash
cp .env.example .env      # local Ollama needs no real API key
```

`.env` keys: `LLM_BASE_URL` (default `http://localhost:11434/v1`), `LLM_API_KEY` (`ollama`),
`LLM_MODEL` (`llama3.1:8b`), `LLM_TEMPERATURE` (default `0`, deterministic).

## Usage

```bash
# Integrated detection + LLM explanation (canonical or syslog input)
python3 log_analyzer.py --input samples/OpenSSH_2k.log --output report
#   -> report.json, report.md
#   optional: --lines-per-chunk N   (default 100; lower it if the model drifts on dense logs)

# Deterministic detector only (no model required)
python3 anomaly_detector.py --input samples/OpenSSH_2k.log --output anomalies

# Regression / evaluation suite (exits non-zero on any failure)
python3 tests/eval/run_eval.py
```

Run either script with `--help` for the full flag list.

## Review console (the app interface)

A self-contained, local web console for reviewing a run in the browser — findings ranked by
severity, per-finding evidence, rule predicate + event timeline, and an integrity manifest.
No build step, no framework, no network.

```bash
# one command: analyze a log and open the reviewed run at http://127.0.0.1:8765/
python3 console/serve.py --input samples/OpenSSH_2k.log

# add --compare to also show what the LLM would have rated each finding on its own
python3 console/serve.py --input sample-2.log --compare

# review an existing report instead of re-analyzing
python3 console/serve.py --report report.json
```

The console runs entirely on `localhost` and reads only local files — the persistent
"processed locally · 0 bytes leave this machine" indicator is literally true.

**Compare mode (`--compare`, opt-in).** Runs a second, *unprimed* LLM pass — the same model
on the same logs but with the deterministic rules removed — to record what the model would
have rated each finding on its own. The console then shows the contrast (RULE verdict vs LLM
alone) and counts how many findings the model under-rated. It is off by default (it doubles
inference) and never alters the authoritative, rule-owned severities.

## Threat-intel enrichment (optional, Stage C prototype)

An opt-in downstream step in [`threat_intel/`](threat_intel/) matches the analyzer's
flagged IPs against threat-intel indicators and resolves each to a MITRE ATT&CK technique
(e.g. a blocked outbound to a known C2 IP → "T1071 — Command and Control"). It runs
*after* the analyzer, reading its report; the core pipeline is untouched. Offline mode
(a local STIX bundle) is the default and needs no extra packages. See
[`threat_intel/README.md`](threat_intel/README.md).

## Design constraints

Data stays local · no model training · read-only (no automated actions) · rules are
authoritative on severity · the validated detector (`anomaly_detector.py`) is kept effectively
frozen, with new formats added as sibling modules.

## Project layout

See §5 of [`PROJECT_HANDOFF.md`](PROJECT_HANDOFF.md) for the full file inventory. Key pieces:
`log_analyzer.py` (analyzer + LLM), `anomaly_detector.py` (validated detector),
`normalize.py` (syslog envelope), `rules_syslog.py` (vocabulary + dedupe),
`rule_context.py` (rule predicate + event timeline for the UI/audit), `compare.py` (opt-in
LLM-alone ablation), `console/` (serve.py + adapter + the review console), `threat_intel/`
(threat-intel enrichment), `tests/eval/` (labeled corpus + harness), `samples/` (real LogHub logs).

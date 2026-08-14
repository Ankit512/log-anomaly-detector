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

## Design constraints

Data stays local · no model training · read-only (no automated actions) · rules are
authoritative on severity · the validated detector (`anomaly_detector.py`) is kept effectively
frozen, with new formats added as sibling modules.

## Project layout

See §5 of [`PROJECT_HANDOFF.md`](PROJECT_HANDOFF.md) for the full file inventory. Key pieces:
`log_analyzer.py` (analyzer + LLM), `anomaly_detector.py` (validated detector),
`normalize.py` (syslog envelope), `rules_syslog.py` (vocabulary + dedupe), `tests/eval/`
(labeled corpus + harness), `samples/` (real LogHub logs).

#!/usr/bin/env python3
"""
log_analyzer.py — Phase 1: AI-powered log analysis (read-only, no auto-actions)

What it does:
  1. Reads a log file (plain text — syslog, app logs, firewall logs, etc.)
  2. Splits it into manageable chunks
  3. Sends each chunk to an LLM with a strict "analyst" prompt
  4. Collects structured findings (severity, category, explanation, recommended action)
  5. Writes a JSON report + a human-readable Markdown summary

This is intentionally READ-ONLY. It does not query live systems, take action,
or auto-remediate anything. That comes in later phases.

Endpoint-agnostic: speaks the OpenAI-compatible Chat Completions API, so the same
code drives local Ollama (the zero-config default) or any hosted provider.
With the default local endpoint, log contents never leave the machine — point
LLM_BASE_URL at a hosted API and they will.

Usage:
  ollama serve                      # if not already running
  ollama pull llama3.1:8b
  python log_analyzer.py --input /path/to/logfile.log --output report

  # or against a hosted OpenAI-compatible endpoint:
  export LLM_BASE_URL=https://api.example.com/v1
  export LLM_API_KEY=sk-...
  export LLM_MODEL=some-model
  python log_analyzer.py --input /path/to/logfile.log --output report

Requirements:
  Python 3 stdlib only. Ollama running on localhost:11434 (default config).
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")
LLM_API_KEY = os.getenv("LLM_API_KEY", "ollama")
LLM_MODEL = os.getenv("LLM_MODEL", "llama3.1:8b")

# 0 keeps reports reproducible: the same log yields the same findings.
try:
    LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0"))
except ValueError:
    print(f"ERROR: LLM_TEMPERATURE must be a number, got {os.getenv('LLM_TEMPERATURE')!r}")
    sys.exit(1)

SYSTEM_PROMPT = """You are a SOC/NOC log analyst. You are given a chunk of raw log lines.

Your job:
- Identify anomalies, errors, security-relevant events, or operational issues.
- Ignore routine/benign log lines — do not report normal operation as a finding.
- For each finding, assign a severity: "info", "low", "medium", "high", "critical".
- Be conservative: if you are not confident something is a real issue, do not report it,
  or mark it "low" and say why you're uncertain.
- Never invent details not present in the logs. If a line is ambiguous, say so.

Respond ONLY with valid JSON (no markdown fences, no preamble), matching this schema:

{
  "findings": [
    {
      "severity": "info|low|medium|high|critical",
      "category": "string, e.g. authentication, network, disk, application_error, security, performance",
      "summary": "one-sentence description of what happened",
      "evidence": "the specific log line(s) or pattern that triggered this finding (short excerpt)",
      "recommended_action": "what a human analyst should check or do next",
      "confidence": "low|medium|high"
    }
  ],
  "chunk_summary": "1-2 sentence overview of what this chunk of logs generally shows"
}

If there are no notable findings in this chunk, return an empty "findings" array.
"""

RETRY_NUDGE = (
    "\n\nYour previous reply was not valid JSON. Reply with the JSON object only — "
    "no prose, no markdown fences."
)


def chunk_log_file(path: Path, lines_per_chunk: int = 100):
    """Yield chunks of the log file as lists of lines."""
    with open(path, "r", errors="replace") as f:
        lines = f.readlines()
    for i in range(0, len(lines), lines_per_chunk):
        yield i, lines[i:i + lines_per_chunk]


def chat_completion(base_url, api_key, model, system, user, timeout=300):
    """POST one prompt to an OpenAI-compatible /chat/completions and return the reply text."""
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": LLM_TEMPERATURE,
        "response_format": {"type": "json_object"},
    }).encode()

    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read())
    return body["choices"][0]["message"]["content"]


def strip_fences(text):
    """Defensive cleanup in case the model wraps in fences despite instructions."""
    return text.replace("```json", "").replace("```", "").strip()


def analyze_chunk(base_url, api_key, model, chunk_lines, chunk_index):
    """Send one chunk to the model and parse the structured response.

    Retries once with a stricter nudge if the first reply is not valid JSON.
    """
    log_text = "".join(chunk_lines)
    user_prompt = f"Analyze this log chunk:\n\n{log_text}"
    raw_text = ""

    for attempt in (1, 2):
        try:
            raw_text = strip_fences(
                chat_completion(base_url, api_key, model, SYSTEM_PROMPT, user_prompt)
            )
        except Exception as e:
            return {
                "findings": [{
                    "severity": "low",
                    "category": "api_error",
                    "summary": f"API call failed: {e}",
                    "evidence": "",
                    "recommended_action": "Retry this chunk or check API connectivity",
                    "confidence": "low",
                }],
                "chunk_summary": "API error on this chunk",
            }

        try:
            parsed = json.loads(raw_text)
            break
        except json.JSONDecodeError:
            if attempt == 2:
                return {
                    "findings": [{
                        "severity": "low",
                        "category": "analysis_error",
                        "summary": "Model response could not be parsed as JSON (after one retry)",
                        "evidence": raw_text[:200],
                        "recommended_action": "Review chunk manually",
                        "confidence": "low",
                    }],
                    "chunk_summary": "Parsing error on this chunk",
                }
            print(f"    chunk {chunk_index + 1}: unparseable JSON, retrying once...")
            user_prompt = f"Analyze this log chunk:\n\n{log_text}{RETRY_NUDGE}"

    parsed["chunk_index"] = chunk_index
    return parsed


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def preflight(base_url, api_key, model):
    """Check the endpoint is reachable. Warn (don't fail) if the model isn't listed."""
    req = urllib.request.Request(
        f"{base_url}/models",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            available = [m.get("id") for m in json.loads(resp.read()).get("data", [])]
    except urllib.error.HTTPError as e:
        # Some providers don't expose /models, or gate it behind other scopes.
        # Not fatal — the real call will surface a clearer error if it matters.
        print(f"WARNING: could not list models at {base_url} (HTTP {e.code}); continuing.")
        return
    except urllib.error.URLError as e:
        print(f"ERROR: cannot reach LLM endpoint at {base_url} ({e.reason}).")
        print("  Local Ollama? Start it with: ollama serve")
        print("  Hosted API? Check LLM_BASE_URL (it should end in /v1).")
        sys.exit(1)

    if available and model not in available:
        print(f"WARNING: model '{model}' not listed at {base_url}.")
        print(f"  available: {', '.join(available) or '(none)'}")
        print(f"  If this is local Ollama, pull it with: ollama pull {model}")


def run(input_path: str, output_prefix: str, lines_per_chunk: int, model: str,
        base_url: str, api_key: str):
    preflight(base_url, api_key, model)

    path = Path(input_path)
    if not path.exists():
        print(f"ERROR: file not found: {input_path}")
        sys.exit(1)

    all_chunks = list(chunk_log_file(path, lines_per_chunk))
    print(f"Loaded {path.name} — {len(all_chunks)} chunk(s) of ~{lines_per_chunk} lines each")
    print(f"Model: {model} (via {base_url})")

    all_findings = []
    chunk_summaries = []

    for idx, (start_line, chunk_lines) in enumerate(all_chunks):
        print(f"  Analyzing chunk {idx + 1}/{len(all_chunks)} (lines {start_line}-{start_line + len(chunk_lines)})...")
        result = analyze_chunk(base_url, api_key, model, chunk_lines, idx)
        for finding in result.get("findings", []):
            finding["chunk_index"] = idx
            finding["approx_line_start"] = start_line
            all_findings.append(finding)
        chunk_summaries.append(result.get("chunk_summary", ""))

    # Sort findings by severity (critical first)
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 5))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(path),
        "model": model,
        "endpoint": base_url,
        "temperature": LLM_TEMPERATURE,
        "total_chunks_analyzed": len(all_chunks),
        "total_findings": len(all_findings),
        "findings": all_findings,
        "chunk_summaries": chunk_summaries,
    }

    json_path = f"{output_prefix}.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    md_path = f"{output_prefix}.md"
    write_markdown_report(report, md_path)

    print(f"\nDone. {len(all_findings)} finding(s) across {len(all_chunks)} chunk(s).")
    print(f"  JSON report: {json_path}")
    print(f"  Markdown report: {md_path}")


def write_markdown_report(report: dict, path: str):
    counts = {}
    for f in report["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    lines = []
    lines.append(f"# Log Analysis Report\n")
    lines.append(f"**Source:** `{report['source_file']}`  ")
    lines.append(f"**Generated:** {report['generated_at']}  ")
    lines.append(f"**Model:** {report.get('model', 'n/a')}  ")
    lines.append(f"**Chunks analyzed:** {report['total_chunks_analyzed']}  ")
    lines.append(f"**Total findings:** {report['total_findings']}\n")

    if counts:
        lines.append("## Severity breakdown\n")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in counts:
                lines.append(f"- **{sev.upper()}**: {counts[sev]}")
        lines.append("")

    lines.append("## Findings\n")
    if not report["findings"]:
        lines.append("No notable findings.\n")
    for f in report["findings"]:
        lines.append(f"### [{f['severity'].upper()}] {f['summary']}")
        lines.append(f"- **Category:** {f.get('category', 'n/a')}")
        lines.append(f"- **Confidence:** {f.get('confidence', 'n/a')}")
        lines.append(f"- **Evidence:** `{f.get('evidence', '')}`")
        lines.append(f"- **Recommended action:** {f.get('recommended_action', 'n/a')}")
        lines.append(f"- **Location:** chunk {f.get('chunk_index')}, near line {f.get('approx_line_start')}")
        lines.append("")

    with open(path, "w") as fh:
        fh.write("\n".join(lines))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-powered log analysis (Phase 1: read-only)")
    parser.add_argument("--input", required=True, help="Path to log file to analyze")
    parser.add_argument("--output", default="report", help="Output file prefix (default: report)")
    parser.add_argument("--lines-per-chunk", type=int, default=100, help="Lines per chunk sent to the model")
    parser.add_argument("--model", default=LLM_MODEL, help=f"Model to use (default: $LLM_MODEL or {LLM_MODEL})")
    parser.add_argument("--base-url", default=LLM_BASE_URL, help=f"OpenAI-compatible base URL (default: $LLM_BASE_URL or {LLM_BASE_URL})")
    args = parser.parse_args()

    run(args.input, args.output, args.lines_per_chunk, args.model, args.base_url, LLM_API_KEY)

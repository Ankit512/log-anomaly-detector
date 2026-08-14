#!/usr/bin/env python3
"""
log_analyzer.py — Phase 1: AI-powered log analysis (read-only, no auto-actions)

What it does:
  1. Reads a log file (plain text — syslog, app logs, firewall logs, etc.)
  2. Splits it into manageable chunks
  3. Sends each chunk to a local Ollama model with a strict "analyst" prompt
  4. Collects structured findings (severity, category, explanation, recommended action)
  5. Writes a JSON report + a human-readable Markdown summary

This is intentionally READ-ONLY. It does not query live systems, take action,
or auto-remediate anything. That comes in later phases.

Runs fully locally — log contents never leave the machine.

Usage:
  ollama serve                      # if not already running
  ollama pull llama3.1:8b
  python log_analyzer.py --input /path/to/logfile.log --output report

Requirements:
  Python 3 stdlib only. Ollama running on localhost:11434.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


MODEL = "llama3.1:8b"
OLLAMA_URL = "http://localhost:11434"

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


def chunk_log_file(path: Path, lines_per_chunk: int = 300):
    """Yield chunks of the log file as lists of lines."""
    with open(path, "r", errors="replace") as f:
        lines = f.readlines()
    for i in range(0, len(lines), lines_per_chunk):
        yield i, lines[i:i + lines_per_chunk]


def ollama_generate(base_url, model, system, prompt, timeout=300):
    """POST one prompt to Ollama's /api/generate and return the response text."""
    payload = json.dumps({
        "model": model,
        "system": system,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0},
    }).encode()

    req = urllib.request.Request(
        f"{base_url}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())["response"]


def analyze_chunk(base_url, model, chunk_lines, chunk_index):
    """Send one chunk to the local model and parse the structured response."""
    log_text = "".join(chunk_lines)
    raw_text = ""

    try:
        raw_text = ollama_generate(
            base_url, model, SYSTEM_PROMPT, f"Analyze this log chunk:\n\n{log_text}"
        ).strip()
        # Defensive cleanup in case the model wraps in fences despite instructions
        raw_text = raw_text.replace("```json", "").replace("```", "").strip()
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        return {
            "findings": [{
                "severity": "low",
                "category": "analysis_error",
                "summary": "Model response could not be parsed as JSON",
                "evidence": raw_text[:200],
                "recommended_action": "Review chunk manually",
                "confidence": "low",
            }],
            "chunk_summary": "Parsing error on this chunk",
        }
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

    parsed["chunk_index"] = chunk_index
    return parsed


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def run(input_path: str, output_prefix: str, lines_per_chunk: int, model: str, base_url: str):
    try:
        with urllib.request.urlopen(f"{base_url}/api/tags", timeout=10) as resp:
            installed = [m["name"] for m in json.loads(resp.read()).get("models", [])]
    except urllib.error.URLError as e:
        print(f"ERROR: cannot reach Ollama at {base_url} ({e}). Start it with: ollama serve")
        sys.exit(1)

    if model not in installed:
        print(f"ERROR: model '{model}' not installed. Pull it with: ollama pull {model}")
        print(f"  installed: {', '.join(installed) or '(none)'}")
        sys.exit(1)

    path = Path(input_path)
    if not path.exists():
        print(f"ERROR: file not found: {input_path}")
        sys.exit(1)

    all_chunks = list(chunk_log_file(path, lines_per_chunk))
    print(f"Loaded {path.name} — {len(all_chunks)} chunk(s) of ~{lines_per_chunk} lines each")
    print(f"Model: {model} (local, via {base_url})")

    all_findings = []
    chunk_summaries = []

    for idx, (start_line, chunk_lines) in enumerate(all_chunks):
        print(f"  Analyzing chunk {idx + 1}/{len(all_chunks)} (lines {start_line}-{start_line + len(chunk_lines)})...")
        result = analyze_chunk(base_url, model, chunk_lines, idx)
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
    parser.add_argument("--lines-per-chunk", type=int, default=300, help="Lines per chunk sent to the model")
    parser.add_argument("--model", default=MODEL, help=f"Ollama model to use (default: {MODEL})")
    parser.add_argument("--ollama-url", default=OLLAMA_URL, help=f"Ollama base URL (default: {OLLAMA_URL})")
    args = parser.parse_args()

    run(args.input, args.output, args.lines_per_chunk, args.model, args.ollama_url)

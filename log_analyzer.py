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
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Deterministic pre-pass. Imported in-process (not shelled out) so anomalies stay
# as dicts. anomaly_detector.py is the validated original and is never modified;
# normalize.py handles the envelope and rules_syslog.py the vocabulary, so v1's
# correlation can run over formats its own regexes were never written for.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import normalize  # noqa: E402
import rules_syslog  # noqa: E402
from anomaly_detector import detect, to_llm_context  # noqa: E402


LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")
LLM_API_KEY = os.getenv("LLM_API_KEY", "ollama")
LLM_MODEL = os.getenv("LLM_MODEL", "llama3.1:8b")

# 0 keeps reports reproducible: the same log yields the same findings.
try:
    LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0"))
except ValueError:
    print(f"ERROR: LLM_TEMPERATURE must be a number, got {os.getenv('LLM_TEMPERATURE')!r}")
    sys.exit(1)

SYSTEM_PROMPT = """You are a SOC/NOC log analyst. You are given a chunk of raw log lines,
preceded by a list of anomalies already pre-flagged by deterministic rule-based detectors.

THE PRE-FLAGGED ANOMALIES ARE AUTHORITATIVE:
- Their severities are decided by validated rules. NEVER change, re-rate, or second-guess them.
- NEVER re-report a pre-flagged anomaly as one of your own findings. It is already in the report.
- Instead, EXPLAIN each pre-flagged anomaly in plain language for a human analyst: what it means,
  why it matters, and what to check. Put these in the "explanations" array, keyed by its rule id.

YOUR FINDINGS ARE FOR ADDITIONAL ISSUES ONLY:
- Report only genuine issues that are NOT already covered by a pre-flagged anomaly.
- Ignore routine/benign log lines — do not report normal operation as a finding.
- Be conservative: if you are not confident something is a real issue, do not report it,
  or mark it "low" and say why you're uncertain.
- Never invent details not present in the logs. If a line is ambiguous, say so.
- If everything notable is already pre-flagged, return an empty "findings" array. That is a
  correct and expected answer — do not invent findings to fill it.

Respond ONLY with valid JSON (no markdown fences, no preamble), matching this schema:

{
  "explanations": [
    {
      "rule_id": "the type of the pre-flagged anomaly you are explaining, e.g. auth_bruteforce_success",
      "explanation": "2-3 sentences a human analyst can act on: what happened, why it matters, what to check"
    }
  ],
  "findings": [
    {
      "severity": "info|low|medium|high|critical",
      "category": "string, e.g. authentication, network, disk, application_error, security, performance",
      "summary": "one-sentence description of what happened",
      "evidence": "the specific log line(s) or pattern that triggered this finding (short excerpt)",
      "recommended_action": "what a human analyst should check or do next",
      "confidence": "low|medium|high",
      "rule_id": null,
      "source": "llm"
    }
  ],
  "chunk_summary": "1-2 sentence overview of what this chunk of logs generally shows"
}
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


def dedupe_anomalies(anomalies):
    """Collapse anomalies identical on (type, summary) into one, keeping an occurrence count.

    The detector legitimately fires once per matching line, so two identical CRIT lines
    produce two byte-identical bullets. Deduping here (not in the detector) keeps the
    validated detector untouched.
    """
    seen = {}
    order = []
    for a in anomalies:
        key = (a.get("type"), a.get("summary"))
        if key in seen:
            seen[key]["occurrences"] += 1
        else:
            copy = dict(a)
            copy["occurrences"] = 1
            seen[key] = copy
            order.append(key)
    return [seen[k] for k in order]


def build_user_prompt(log_text, ctx, suffix=""):
    """Build the user message. THE single place the prompt is assembled.

    Both the first attempt and the retry go through here, so pre-flagged context can
    never be dropped on a retry.
    """
    return f"{ctx}\n\nAnalyze this log chunk:\n\n{log_text}{suffix}"


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


def analyze_chunk(base_url, api_key, model, chunk_lines, chunk_index, ctx):
    """Send one chunk to the model and parse the structured response.

    Retries once with a stricter nudge if the first reply is not valid JSON.
    """
    log_text = "".join(chunk_lines)
    user_prompt = build_user_prompt(log_text, ctx)
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
            # Same helper as the first attempt — the retry keeps the pre-flagged context.
            user_prompt = build_user_prompt(log_text, ctx, suffix=RETRY_NUDGE)

    parsed["chunk_index"] = chunk_index
    return parsed


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def severity_rank(finding):
    """Sort key. Case-insensitive: detector findings carry uppercase severities."""
    return SEVERITY_ORDER.get(str(finding.get("severity", "info")).lower(), 5)


def detector_to_findings(anomalies):
    """Map deduped detector anomalies into the analyzer's finding schema.

    These are authoritative: severity comes from the rules, not the model.
    """
    findings = []
    for a in anomalies:
        findings.append({
            "severity": str(a.get("severity", "info")).upper(),
            "category": "rule_detection",
            "summary": a.get("summary", ""),
            "evidence": a.get("evidence", ""),
            "rationale": a.get("rationale", ""),
            "recommended_action": "",   # filled from the model's explanation when available
            "confidence": "high",
            "rule_id": a.get("type"),
            "source": "detector",
            "entities": a.get("entities", {}),
            "occurrences": a.get("occurrences", 1),
        })
    return findings


TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T[\d:]+(?:Z|[+-]\d{2}:\d{2})?")


def restates_detector(finding, anomalies):
    """Best-effort: does this LLM finding just restate a pre-flagged anomaly?

    Matches on distinctive markers only — IPs, ports, and the timestamps of the exact
    log lines the rule fired on. Hosts and usernames are deliberately excluded: they
    recur across unrelated lines, so matching on them would discard legitimate
    additional findings. A shared timestamp means the same log line, so it is safe.
    """
    text = " ".join(f"{finding.get('summary', '')} {finding.get('evidence', '')}".lower().split())
    for a in anomalies:
        ents = a.get("entities", {})
        markers = [str(ents[k]).lower() for k in ("ip", "dest_ip") if ents.get(k)]
        if ents.get("port"):
            markers.append(f":{ents['port']}")
        markers += [t.lower() for t in TIMESTAMP_RE.findall(a.get("evidence", ""))]
        if markers and any(m in text for m in markers):
            return True
    return False


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

    # --- Deterministic pre-pass: rules run over the WHOLE file before any LLM call ---
    records, stats = normalize.load(path)
    print(f"Format: {stats['format']} — {stats['parsed']}/{stats['total_lines']} line(s) parsed"
          + (f", {stats['unparsed']} unparsed" if stats["unparsed"] else ""))
    if stats["unparsed"]:
        for raw in stats["unparsed_examples"][:3]:
            print(f"    unparsed: {raw[:88]}")

    extra_anomalies = []
    if stats["format"] == "rfc3164":
        records, counts = rules_syslog.canonicalize(records)
        print(f"Vocabulary: translated {counts['auth_fail']} auth-failure and "
              f"{counts['auth_ok']} auth-success message(s) into rule vocabulary")
        extra_anomalies = rules_syslog.detect_extra(records)

    raw_anomalies = detect(records) + extra_anomalies
    anomalies = dedupe_anomalies(raw_anomalies)
    collapsed = len(raw_anomalies) - len(anomalies)
    print(f"Detector: {len(anomalies)} anomaly(ies)"
          + (f" ({collapsed} duplicate(s) collapsed)" if collapsed else ""))
    ctx = to_llm_context(anomalies)

    all_chunks = list(chunk_log_file(path, lines_per_chunk))
    print(f"Loaded {path.name} — {len(all_chunks)} chunk(s) of ~{lines_per_chunk} lines each")
    print(f"Model: {model} (via {base_url})")

    llm_findings = []
    chunk_summaries = []
    explanations = {}

    for idx, (start_line, chunk_lines) in enumerate(all_chunks):
        print(f"  Analyzing chunk {idx + 1}/{len(all_chunks)} (lines {start_line}-{start_line + len(chunk_lines)})...")
        result = analyze_chunk(base_url, api_key, model, chunk_lines, idx, ctx)

        for ex in result.get("explanations", []):
            rid = ex.get("rule_id")
            if rid and rid not in explanations and ex.get("explanation"):
                explanations[rid] = ex["explanation"]

        for finding in result.get("findings", []):
            if restates_detector(finding, anomalies):
                print(f"    dropped LLM finding (restates a pre-flagged anomaly): {finding.get('summary', '')[:60]}")
                continue
            finding["chunk_index"] = idx
            finding["approx_line_start"] = start_line
            finding["rule_id"] = None
            finding["source"] = "llm"       # set here, never trusted from the model
            llm_findings.append(finding)
        chunk_summaries.append(result.get("chunk_summary", ""))

    # Detector findings are authoritative and added ONCE, not per chunk.
    detector_findings = detector_to_findings(anomalies)
    for f in detector_findings:
        if f["rule_id"] in explanations:
            f["recommended_action"] = explanations[f["rule_id"]]

    # Sort each group by severity (critical first); detector findings lead the report.
    detector_findings.sort(key=severity_rank)
    llm_findings.sort(key=severity_rank)
    all_findings = detector_findings + llm_findings

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(path),
        "model": model,
        "endpoint": base_url,
        "temperature": LLM_TEMPERATURE,
        "total_chunks_analyzed": len(all_chunks),
        "total_findings": len(all_findings),
        "findings_by_source": {
            "detector": len(detector_findings),
            "llm": len(llm_findings),
        },
        "findings": all_findings,
        "chunk_summaries": chunk_summaries,
    }

    json_path = f"{output_prefix}.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    md_path = f"{output_prefix}.md"
    write_markdown_report(report, md_path)

    print(f"\nDone. {len(all_findings)} finding(s) across {len(all_chunks)} chunk(s) "
          f"({len(detector_findings)} from rules, {len(llm_findings)} from the model).")
    print(f"  JSON report: {json_path}")
    print(f"  Markdown report: {md_path}")


def write_markdown_report(report: dict, path: str):
    counts = {}
    for f in report["findings"]:
        sev = str(f.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1

    by_source = report.get("findings_by_source", {})

    lines = []
    lines.append(f"# Log Analysis Report\n")
    lines.append(f"**Source:** `{report['source_file']}`  ")
    lines.append(f"**Generated:** {report['generated_at']}  ")
    lines.append(f"**Model:** {report.get('model', 'n/a')}  ")
    lines.append(f"**Chunks analyzed:** {report['total_chunks_analyzed']}  ")
    lines.append(f"**Total findings:** {report['total_findings']} "
                 f"({by_source.get('detector', 0)} rule-based, {by_source.get('llm', 0)} model)\n")

    if counts:
        lines.append("## Severity breakdown\n")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in counts:
                lines.append(f"- **{sev.upper()}**: {counts[sev]}")
        lines.append("")

    detector = [f for f in report["findings"] if f.get("source") == "detector"]
    llm = [f for f in report["findings"] if f.get("source") != "detector"]

    def render(f):
        occ = f.get("occurrences", 1)
        title = f"### [{str(f['severity']).upper()}] {f['summary']}"
        lines.append(title + (f" _(x{occ})_" if occ > 1 else ""))
        if f.get("rule_id"):
            lines.append(f"- **Rule:** `{f['rule_id']}`")
        lines.append(f"- **Source:** {f.get('source', 'llm')}")
        lines.append(f"- **Category:** {f.get('category', 'n/a')}")
        lines.append(f"- **Confidence:** {f.get('confidence', 'n/a')}")
        lines.append(f"- **Evidence:** `{f.get('evidence', '')}`")
        if f.get("rationale"):
            lines.append(f"- **Why the rule fired:** {f['rationale']}")
        action = f.get("recommended_action") or "n/a"
        label = "Analyst explanation" if f.get("source") == "detector" else "Recommended action"
        lines.append(f"- **{label}:** {action}")
        if f.get("source") != "detector":
            lines.append(f"- **Location:** chunk {f.get('chunk_index')}, near line {f.get('approx_line_start')}")
        lines.append("")

    lines.append("## Rule-based findings (authoritative)\n")
    if not detector:
        lines.append("No rule-based anomalies detected.\n")
    for f in detector:
        render(f)

    lines.append("## Additional findings from the model\n")
    if not llm:
        lines.append("None — the model surfaced nothing beyond the pre-flagged anomalies.\n")
    for f in llm:
        render(f)

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

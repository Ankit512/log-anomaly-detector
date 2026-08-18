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
import hashlib
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
import rule_context  # noqa: E402
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

RULESET_VERSION = "v1"

# Gap-fill = asking the model about chunks NO rule fired on, to catch sub-threshold
# things like "disk at 78%". It is the only reason to send a chunk containing no
# finding, and on a large log it is also the entire cost: 2,000 lines is 80 chunks,
# nearly all empty. So it runs automatically only on inputs small enough to be
# cheap, and is opt-in beyond that via --deep-scan.
GAP_FILL_MAX_CHUNKS = 4

# No completion cap. Measured: a cap of 320 truncated real explanation replies —
# sample-2 went from 5 findings with prose to 4 with none — while saving nothing
# (13.6s vs 13.7s per call, because generation was never the bottleneck; a 1,661-token
# prompt and model reloads were). A cap that silently empties the report is a bad
# trade at any speed, so the knob is gone rather than tuned.
MAX_COMPLETION_TOKENS = None

# Explanations are generated eagerly for only the most severe findings; the rest are
# produced on demand when a reviewer opens them. Wall time for a run is then bounded
# by this number, not by the size of the log — a 2,000-line file with 18 findings
# costs the same first-paint as a 19-line one. Rules still cover every line.
EAGER_EXPLANATIONS = 3

# A chunk we already read can still come back with a finding unexplained: the model
# skips a rule id, or writes one explanation for two same-type findings and names only
# one host. Those used to render "n/a" forever. We re-ask for each such finding
# individually — the chunk is already selected, so this is prose we meant to have.
# Bounded, because in --deep-scan every chunk is selected and the tail is not worth
# minutes of wall time; whatever is left over is still explained on demand.
SECOND_PASS_MAX = 6

# Ollama unloads an idle model after ~5 minutes by default, so the first call of a
# run pays ~9s of load time. Pinning it at preflight removes that from the run.
OLLAMA_KEEP_ALIVE = "30m"

# Machine-readable progress for console/serve.py. Off by default so CLI output stays
# prose; serve.py sets LOG_ANALYZER_PROGRESS=1 and parses these lines.
_PROGRESS = os.getenv("LOG_ANALYZER_PROGRESS") == "1"


def progress(**fields):
    if _PROGRESS:
        print("PROGRESS " + json.dumps(fields), flush=True)


FINDING_LINES_RE = re.compile(r"lines (\d+)-(\d+)")


def finding_line_numbers(anomaly):
    """Every source line this finding points at, from its timeline and evidence."""
    lines = {e["line"] for e in anomaly.get("timeline", []) if e.get("line")}
    m = FINDING_LINES_RE.search(anomaly.get("evidence") or "")
    if m:
        lines |= {int(m.group(1)), int(m.group(2))}
    return lines


def chunks_with_findings(anomalies, lines_per_chunk, chunk_count):
    """Indices of chunks that actually contain a detector finding.

    This is the whole performance story. The detector reads every line for free;
    the model is only needed to explain what the detector found. Sending it the
    other 70% of a large log costs minutes and buys nothing, because a finding it
    produced there would have no rule behind it anyway.
    """
    wanted = set()
    for a in anomalies:
        for line in finding_line_numbers(a):
            idx = (line - 1) // lines_per_chunk
            if 0 <= idx < chunk_count:
                wanted.add(idx)
    return wanted


def should_run_model(stats):
    """Run the LLM pass only when the parser actually structured something.

    When 0 lines parse, no rule has evaluated anything, so there is nothing for the
    model to explain and nothing to check its output against. Running it anyway
    produces unvalidated guesses over text we cannot read — measured on a macOS
    unified log, that was 21 spurious LOW findings about routine OS events, which
    then read on the console as coverage the run never had.

    Rules-first is the thesis: no structure, no analysis. Say so instead.
    """
    return stats.get("parsed", 0) > 0


def file_sha256(path):
    """Integrity hash for the run manifest.

    Recomputable by anyone holding the file. This is an INTEGRITY check, not a
    signature — nothing here attests to who produced the run, and the UI must
    never present it as if it did.
    """
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(65536), b""):
                h.update(block)
    except OSError:
        return None
    return h.hexdigest()


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

SCHEMA_NUDGE = (
    "\n\nYour previous reply was valid JSON but had the WRONG SHAPE. It must be a JSON "
    'object whose top-level keys are exactly "explanations" (array), "findings" (array) '
    'and "chunk_summary" (string). Do not invent other top-level keys such as "log" or '
    '"events". Put every issue you found inside the "findings" array.'
)


def chunk_log_file(path: Path, lines_per_chunk: int = 25):
    """Yield chunks of the log file as lists of lines.

    25, not 100. llama3.1:8b abandons the response schema on ~100 lines of dense
    real logs — measured three times (T5a, the compare benchmark, and a field test
    on unseen OpenSSH lines, where a 100-line chunk produced analyzer_error and no
    explanation at all). At 25 lines the benchmark saw 0 of 21 chunks degrade.

    The trade-off is ~4x more model calls per log, and a chattier model (smaller
    windows surface more below-threshold notes). This affects ONLY the LLM pass:
    the detector reads every line of the file regardless, so rule severities and
    correlation are identical at any chunk size.
    """
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


def validate_response(obj):
    """Does the reply have the SHAPE the system prompt asked for?

    response_format=json_object guarantees only that the reply *parses*. Small models
    routinely return well-formed JSON of the wrong shape (e.g. {"log": [...]}), which
    a parseability-only check accepts and .get("findings", []) then silently reads as
    "no findings" — a false all-clear on a log full of real events.

    Drift also happens one level down: a correct "findings" list whose items use the
    model's own keys ("finding"/"description" instead of "summary"). Those render as
    empty placeholders and slip past restatement dedupe, so items are checked too.
    An empty findings list stays valid — "nothing beyond the pre-flagged anomalies"
    is a legitimate answer.
    """
    if not isinstance(obj, dict) or not isinstance(obj.get("findings"), list):
        return False
    return all(_valid_finding(f) for f in obj["findings"])


def _valid_finding(f):
    return isinstance(f, dict) and isinstance(f.get("summary"), str) and bool(f["summary"].strip())


def describe_schema_failure(obj):
    """Say which layer drifted, so the report's evidence is actually diagnostic."""
    if not isinstance(obj, dict):
        return f"reply was a JSON {type(obj).__name__}, not an object"
    if not isinstance(obj.get("findings"), list):
        return f"no 'findings' array; top-level keys: {list(obj.keys())}"
    bad = [sorted(f.keys()) if isinstance(f, dict) else type(f).__name__
           for f in obj["findings"] if not _valid_finding(f)]
    return f"{len(bad)} findings[] item(s) lack a usable 'summary'; item keys: {bad[:2]}"


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

        parsed = None
        problem = None
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError:
            problem = "unparseable"
        else:
            if not validate_response(parsed):
                problem = "off-schema"

        if problem is None:
            break

        if attempt == 2:
            if problem == "unparseable":
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
            # Off-schema twice: fail LOUDLY. An empty findings list here would be a
            # false all-clear for a chunk that was never actually analyzed.
            return {
                "findings": [{
                    "severity": "HIGH",
                    "category": "analyzer_error",
                    "summary": "Model returned off-schema response; chunk not analyzed",
                    "evidence": describe_schema_failure(parsed),
                    "recommended_action": (
                        "This chunk was NOT analyzed by the model — treat it as unreviewed. "
                        "Retry with a smaller --lines-per-chunk or a larger model."
                    ),
                    "confidence": "high",
                    "rule_id": "analyzer_error",
                    "source": "analyzer",
                }],
                "chunk_summary": "Off-schema response on this chunk",
            }

        nudge = RETRY_NUDGE if problem == "unparseable" else SCHEMA_NUDGE
        print(f"    chunk {chunk_index + 1}: {problem} response, retrying once...")
        # Same helper as the first attempt — the retry keeps the pre-flagged context.
        user_prompt = build_user_prompt(log_text, ctx, suffix=nudge)

    parsed["chunk_index"] = chunk_index
    return parsed


def explain_single(base_url, api_key, model, chunk_lines, chunk_index, ctx,
                   rule_id=None, ident=None):
    """Ask for the prose of ONE finding and return it, or "" if nothing usable came back.

    The context names a single finding, so an explanation with no rule id is taken to
    be about it. `ident` (an IP or host) is the tie-break for the one case where that
    assumption breaks: two findings of the same type in the same chunk. Prose about the
    wrong host is worse than no prose, so a reply that never names `ident` is refused.

    Shared by the analyzer's second pass and the console's on-demand button so both
    accept an answer on exactly the same terms.
    """
    result = analyze_chunk(base_url, api_key, model, chunk_lines, chunk_index, ctx)
    for ex in result.get("explanations", []):
        text = ex.get("explanation")
        if not text:
            continue
        rid = ex.get("rule_id")
        if rid and rule_id and rid != rule_id:
            continue
        if ident and ident not in text:
            continue
        return text
    return ""


def anomaly_ident(anomaly):
    """The address or host that identifies a finding, when it has one."""
    ents = anomaly.get("entities") or {}
    return next((str(ents[k]) for k in ("ip", "dest_ip", "host") if ents.get(k)), None)


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
            "predicate": a.get("predicate", ""),
            "timeline": a.get("timeline", []),
        })
    return findings


TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T[\d:]+(?:Z|[+-]\d{2}:\d{2})?")

# v1's canonical auth-failure phrasing, read back out of the record stream.
CANON_AUTH_FAIL_RE = re.compile(r"auth failed for user '(?P<user>[^']*)' from (?P<ip>\S+)")

SPRAY_MIN_USERS = 2          # below this it isn't a spray, it's one target
SPRAY_NAMES_SHOWN = 4


def usernames_by_ip(records):
    """Distinct usernames each IP attempted, in first-seen order.

    v1's brute-force finding names only the first username it saw, which is
    accurate but misleading when an attacker sprays many accounts. The record
    stream already holds every attempt, so the full picture is derivable here
    without touching the detector.
    """
    seen = {}
    for r in records:
        m = CANON_AUTH_FAIL_RE.search(r.get("msg", ""))
        if not m:
            continue
        user = m.group("user")
        bucket = seen.setdefault(m.group("ip"), [])
        if user not in bucket:
            bucket.append(user)
    return seen


def enrich_username_spray(anomalies, records):
    """Add distinct-username context to brute-force findings. Mutates copies only."""
    users = usernames_by_ip(records)
    for a in anomalies:
        if a.get("type") not in ("auth_bruteforce", "auth_bruteforce_success"):
            continue
        ip = a.get("entities", {}).get("ip")
        attempted = users.get(ip, [])
        a.setdefault("entities", {})["distinct_usernames"] = len(attempted)
        a["entities"]["usernames_sample"] = attempted[:SPRAY_NAMES_SHOWN]
        if len(attempted) < SPRAY_MIN_USERS:
            continue
        shown = ", ".join(attempted[:SPRAY_NAMES_SHOWN])
        more = f", +{len(attempted) - SPRAY_NAMES_SHOWN} more" if len(attempted) > SPRAY_NAMES_SHOWN else ""
        a["summary"] = (f"{a['summary']} — {len(attempted)} distinct usernames sprayed "
                        f"({shown}{more})")
    return anomalies


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

    # Best-effort: ask Ollama to keep the model resident for the run. Ignored by
    # non-Ollama endpoints, and never fatal — it is a latency optimisation only.
    try:
        pin = json.dumps({"model": model, "prompt": "", "keep_alive": OLLAMA_KEEP_ALIVE,
                          "stream": False}).encode()
        root = base_url[:-3] if base_url.rstrip("/").endswith("/v1") else base_url
        req = urllib.request.Request(root.rstrip("/") + "/api/generate", data=pin,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120):
            pass
    except Exception:
        pass

    if available and model not in available:
        print(f"WARNING: model '{model}' not listed at {base_url}.")
        print(f"  available: {', '.join(available) or '(none)'}")
        print(f"  If this is local Ollama, pull it with: ollama pull {model}")


def run(input_path: str, output_prefix: str, lines_per_chunk: int, model: str,
        base_url: str, api_key: str, compare: bool = False, deep_scan: bool = False):
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
        # Collapse sshd's multiple lines per attempt so failure counts are real
        # attempts, not log lines. Runs AFTER detect_extra so break-in warnings,
        # which are counted per line, are unaffected.
        records, dropped = rules_syslog.dedupe_auth_attempts(records)
        if dropped:
            print(f"Dedupe: collapsed {dropped} companion line(s); "
                  f"{counts['auth_fail'] - dropped} auth event(s) = real attempts")

    raw_anomalies = detect(records) + extra_anomalies
    # Derived from the same record stream v1 just consumed — v1 itself is untouched.
    raw_anomalies = enrich_username_spray(raw_anomalies, records)
    # Rule predicate + event sequence for the report and the review console.
    # Deterministic: restated constants and reordered records, no model call.
    raw_anomalies = rule_context.enrich(raw_anomalies, records)
    anomalies = dedupe_anomalies(raw_anomalies)
    collapsed = len(raw_anomalies) - len(anomalies)
    print(f"Detector: {len(anomalies)} anomaly(ies)"
          + (f" ({collapsed} duplicate(s) collapsed)" if collapsed else ""))
    ctx = to_llm_context(anomalies)

    run_model = should_run_model(stats)
    all_chunks = list(chunk_log_file(path, lines_per_chunk)) if run_model else []

    llm_findings = []
    chunk_summaries = []
    explanations = {}

    # Which chunks does the model actually need to see?
    if run_model:
        finding_chunks = chunks_with_findings(anomalies, lines_per_chunk, len(all_chunks))
        gap_fill = deep_scan or len(all_chunks) <= GAP_FILL_MAX_CHUNKS
        if gap_fill:
            selected = sorted(range(len(all_chunks)))
        else:
            # Only the chunks holding the most severe findings are explained up front.
            # Everything else is explained when a reviewer actually opens it.
            top = sorted(anomalies, key=severity_rank)[:EAGER_EXPLANATIONS]
            # One chunk per finding — the one where it culminates — not every chunk it
            # touches. A brute-force cluster spans several chunks; explaining all of
            # them up front triples first-paint for no extra explanation.
            eager = set()
            for a in top:
                lines = finding_line_numbers(a)
                if lines:
                    eager.add((max(lines) - 1) // lines_per_chunk)
            selected = sorted(eager)
        deferred = sorted(finding_chunks - set(selected))
        # Per-chunk context: only the findings that live IN each chunk. Sending the
        # whole run's context to every chunk made each prompt grow with the number of
        # findings — and asking the model to explain a finding from lines it cannot
        # see was never coherent anyway.
        by_chunk = {}
        for pos, a in enumerate(anomalies):
            for line in finding_line_numbers(a):
                i = (line - 1) // lines_per_chunk
                if 0 <= i < len(all_chunks) and pos not in by_chunk.setdefault(i, []):
                    by_chunk[i].append(pos)
        chunk_ctx = {i: to_llm_context([anomalies[j] for j in v])
                     for i, v in by_chunk.items()}
        empty_ctx = to_llm_context([])
    else:
        gap_fill, selected, chunk_ctx, empty_ctx = False, [], {}, ""
        deferred = []

    if not run_model:
        print(f"Skipping the model: 0 of {stats['total_lines']} line(s) parsed, so no rule "
              f"evaluated anything.")
        print("  Analyzing unparseable text would be guesswork with nothing to check it "
              "against — reporting 'format not recognized' instead.")
    else:
        print(f"Loaded {path.name} — {len(all_chunks)} chunk(s) of ~{lines_per_chunk} lines each")
        print(f"Model: {model} (via {base_url})")
        if gap_fill:
            why = "--deep-scan" if deep_scan else f"small input (<= {GAP_FILL_MAX_CHUNKS} chunks)"
            print(f"  Explaining all {len(selected)} chunk(s) — {why}, so sub-threshold notes "
                  f"are included.")
        else:
            print(f"  Explaining {len(selected)} chunk(s) now — the {EAGER_EXPLANATIONS} most "
                  f"severe finding(s). {len(deferred)} more chunk(s) are explained on demand "
                  f"when a finding is opened.")
            print(f"  The detector already read all {len(all_chunks)} chunk(s); "
                  f"--deep-scan explains everything up front instead.")

    # Detector findings are instant; explanations are not. Publish a rules-only report
    # immediately so the console can show real findings in about a second, then
    # overwrite it when explanations land. A multi-minute blank screen is
    # indistinguishable from a hang, and the findings were ready the whole time.
    if run_model and selected:
        early = detector_to_findings(anomalies)
        early.sort(key=severity_rank)
        Path(f"{output_prefix}.json").write_text(json.dumps({
            "partial": True, "generated_at": datetime.now(timezone.utc).isoformat(),
            "source_file": str(path), "model": model, "endpoint": base_url,
            "temperature": LLM_TEMPERATURE, "ruleset": RULESET_VERSION,
            "lines_parsed": stats["parsed"], "lines_unparsed": stats["unparsed"],
            "input_sha256": file_sha256(path),
            "detector_sha256": file_sha256(Path(__file__).resolve().parent / "anomaly_detector.py"),
            "total_chunks": len(all_chunks), "total_chunks_analyzed": len(selected),
            "gap_fill": gap_fill,
        "deferred_chunks": list(deferred),
        "eager_explanations": EAGER_EXPLANATIONS, "total_findings": len(early),
            "findings_by_source": {"detector": len(early), "llm": 0, "analyzer": 0},
            "findings": early, "chunk_summaries": [],
        }, indent=2))
        progress(phase="rules", partialReady=True, findings=len(anomalies))

    progress(phase="explain", done=0, total=len(selected), findings=len(anomalies),
             chunks=len(all_chunks), gapFill=gap_fill)

    for step, idx in enumerate(selected, start=1):
        start_line, chunk_lines = all_chunks[idx]
        print(f"  Explaining chunk {idx + 1}/{len(all_chunks)} "
              f"({step}/{len(selected)}, lines {start_line}-{start_line + len(chunk_lines)})...")
        result = analyze_chunk(base_url, api_key, model, chunk_lines, idx,
                               chunk_ctx.get(idx, empty_ctx))
        progress(phase="explain", done=step, total=len(selected), chunk=idx + 1)

        # Tie each explanation to the findings in THIS chunk with that rule id.
        # Keying by rule id alone pasted one chunk's prose onto every finding of the
        # same type — an explanation naming 112.95.230.3 appeared on findings about
        # entirely different addresses, which is worse than showing nothing.
        here = by_chunk.get(idx, [])
        for ex in result.get("explanations", []):
            rid, text = ex.get("rule_id"), ex.get("explanation")
            if not text:
                continue
            targets = [j for j in here if anomalies[j].get("type") == rid] or \
                      ([here[0]] if len(here) == 1 and not rid else [])
            for j in targets:
                # When a chunk holds two findings of the same type the model writes
                # one explanation, usually naming only one of them. Attach it only
                # where the prose actually refers to that finding; the others stay
                # pending and get their own on demand. Prose about the wrong host is
                # worse than no prose.
                ident = anomaly_ident(anomalies[j])
                if ident and ident not in text:
                    continue
                explanations.setdefault(j, text)

        for finding in result.get("findings", []):
            # Analyzer-generated findings (e.g. off-schema failures) are ours, not the
            # model's: never deduped away, never relabelled.
            if finding.get("source") == "analyzer":
                finding["chunk_index"] = idx
                finding["approx_line_start"] = start_line
                llm_findings.append(finding)
                continue
            if restates_detector(finding, anomalies):
                print(f"    dropped LLM finding (restates a pre-flagged anomaly): {finding.get('summary', '')[:60]}")
                continue
            finding["chunk_index"] = idx
            finding["approx_line_start"] = start_line
            finding["rule_id"] = None
            finding["source"] = "llm"       # set here, never trusted from the model
            # The model sometimes omits fields even in a shape-valid findings list.
            finding.setdefault("severity", "info")
            finding.setdefault("summary", "(model omitted a summary for this finding)")
            llm_findings.append(finding)
        chunk_summaries.append(result.get("chunk_summary", ""))

    # Second pass: findings whose chunk we already explained but which came back
    # without prose. Asking again for one finding at a time removes the ambiguity that
    # lost them the first time — the context names one finding, so there is nothing for
    # the model to conflate. Deferred chunks are deliberately NOT pulled in here; those
    # are the on-demand budget and re-asking them would undo the wall-time bound.
    missing = [j for idx in selected for j in by_chunk.get(idx, [])
               if j not in explanations]
    if missing:
        retry, skipped = missing[:SECOND_PASS_MAX], missing[SECOND_PASS_MAX:]
        print(f"  {len(missing)} finding(s) came back unexplained; re-asking for "
              f"{len(retry)} individually...")
        if skipped:
            print(f"    {len(skipped)} left for on-demand (cap is {SECOND_PASS_MAX} "
                  f"per run) — they keep their rule verdict and evidence either way.")
        for j in retry:
            idx = next(i for i in selected if j in by_chunk.get(i, []))
            _, chunk_lines = all_chunks[idx]
            same_type = sum(1 for k in by_chunk.get(idx, [])
                            if anomalies[k].get("type") == anomalies[j].get("type"))
            text = explain_single(
                base_url, api_key, model, chunk_lines, idx,
                to_llm_context([anomalies[j]]),
                rule_id=anomalies[j].get("type"),
                # Only enforce the identity check when there is actually a same-type
                # sibling in this chunk to confuse it with.
                ident=anomaly_ident(anomalies[j]) if same_type > 1 else None)
            if text:
                explanations[j] = text
            else:
                print(f"    still unexplained: {anomalies[j].get('type')} "
                      f"(kept as pending, not as an empty answer)")

    # Detector findings are authoritative and added ONCE, not per chunk.
    detector_findings = detector_to_findings(anomalies)
    # detector_to_findings preserves anomaly order, so position maps 1:1.
    for pos, f in enumerate(detector_findings):
        if pos in explanations:
            f["recommended_action"] = explanations[pos]

    # --- Optional ablation: what would the model alone have said? ---------------
    # Strictly additive. Runs a SECOND, unprimed pass over the same chunks and
    # annotates the detector findings; it never touches their severities.
    compare_stats = None
    if compare and not run_model:
        print("Compare mode skipped: nothing was parsed, so there is no rule verdict to "
              "compare the model against.")
    if compare and run_model:
        import compare as compare_mod
        print("Compare mode: second unprimed pass (no rules, no pre-flags)...")

        def chat_fn(system, user):
            return chat_completion(base_url, api_key, model, system, user)

        # Same scoping: an LLM-alone verdict only means something for a chunk that
        # has a rule verdict to compare it against.
        compare_chunks = [all_chunks[i][1] for i in selected]
        progress(phase="compare", done=0, total=len(compare_chunks))
        llm_alone, statuses = compare_mod.run_llm_alone(
            compare_chunks, chat_fn, model, LLM_TEMPERATURE, strip_fences)
        ok = sum(1 for s in statuses if s in compare_mod.USABLE_STATUSES)
        coverage_ok = ok == len(statuses)
        print(f"  unprimed pass: {ok}/{len(statuses)} chunk(s) usable, "
              f"{len(llm_alone)} finding(s)")
        if not coverage_ok:
            bad = [s for s in statuses if s not in compare_mod.USABLE_STATUSES]
            print(f"  WARNING: {len(bad)} chunk(s) gave no usable answer ({', '.join(sorted(set(bad)))}).")
            print("           Findings in those ranges are UNKNOWN, not 'missed' — the")
            print("           comparison cannot speak for lines the model never rated.")

        compare_mod.align(detector_findings, llm_alone, records, coverage_ok=coverage_ok)
        compare_stats = {
            "chunks_total": len(statuses),
            "chunks_usable": ok,
            "chunk_status": statuses,
            "llm_alone_findings": len(llm_alone),
            "underrated_count": compare_mod.underrated_count(detector_findings),
            "prompt": compare_mod.PROMPT_VERSION,
        }
        print(f"  under-rated by the model alone: {compare_stats['underrated_count']}"
              f"/{len(detector_findings)} rule finding(s)")

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
        "ruleset": RULESET_VERSION,
        "lines_parsed": stats["parsed"],
        "lines_unparsed": stats["unparsed"],
        "input_sha256": file_sha256(path),
        "detector_sha256": file_sha256(Path(__file__).resolve().parent / "anomaly_detector.py"),
        "total_chunks": len(all_chunks),
        "total_chunks_analyzed": len(selected),
        "gap_fill": gap_fill,
        "deferred_chunks": list(deferred),
        "eager_explanations": EAGER_EXPLANATIONS,
        "total_findings": len(all_findings),
        # An analyzer_error is a failure to analyze, not a contribution. Counting it
        # under "llm" overstated model participation in exactly the runs where the
        # model produced nothing at all.
        "findings_by_source": {
            "detector": len(detector_findings),
            "llm": len([f for f in llm_findings if f.get("source") == "llm"]),
            "analyzer": len([f for f in llm_findings if f.get("source") == "analyzer"]),
        },
        "findings": all_findings,
        "chunk_summaries": chunk_summaries,
    }
    if compare_stats:
        report["compare"] = compare_stats

    json_path = f"{output_prefix}.json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    md_path = f"{output_prefix}.md"
    write_markdown_report(report, md_path)

    model_count = report["findings_by_source"]["llm"]
    analyzer_count = report["findings_by_source"]["analyzer"]
    parts = [f"{len(detector_findings)} from rules"]
    parts.append(f"{model_count} from the model" if model_count
                 else "the model contributed none")
    if analyzer_count:
        parts.append(f"{analyzer_count} chunk(s) the model could not analyze")
    print(f"\nDone. {len(all_findings)} finding(s) across {len(all_chunks)} chunk(s) "
          f"({', '.join(parts)}).")
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
        title = f"### [{str(f.get('severity', 'info')).upper()}] {f.get('summary', '(no summary)')}"
        lines.append(title + (f" _(x{occ})_" if occ > 1 else ""))
        if f.get("rule_id"):
            lines.append(f"- **Rule:** `{f['rule_id']}`")
        lines.append(f"- **Source:** {f.get('source', 'llm')}")
        lines.append(f"- **Category:** {f.get('category', 'n/a')}")
        lines.append(f"- **Confidence:** {f.get('confidence', 'n/a')}")
        lines.append(f"- **Evidence:** `{f.get('evidence', '')}`")
        if f.get("rationale"):
            lines.append(f"- **Why the rule fired:** {f['rationale']}")
        # "n/a" read like "nothing to do here". A detector finding without prose is a
        # finding the model has not been asked about yet — the rule verdict, evidence
        # and rationale above it are complete and unaffected.
        action = f.get("recommended_action") or (
            "_not generated — open this finding in the console to explain it_"
            if f.get("source") == "detector" else "n/a")
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

    lines.append("## Additional findings (model + analyzer)\n")
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
    parser.add_argument("--lines-per-chunk", type=int, default=25,
                        help="Lines per chunk sent to the model (default 25 — larger "
                             "chunks make an 8B model drop the response schema; the "
                             "detector is unaffected either way)")
    parser.add_argument("--model", default=LLM_MODEL, help=f"Model to use (default: $LLM_MODEL or {LLM_MODEL})")
    parser.add_argument("--base-url", default=LLM_BASE_URL, help=f"OpenAI-compatible base URL (default: $LLM_BASE_URL or {LLM_BASE_URL})")
    parser.add_argument("--compare", action="store_true",
                        help="Also run an unprimed LLM-alone pass and record what the model "
                             "would have rated each finding without the rules. Doubles "
                             "inference cost; never changes an authoritative severity.")
    parser.add_argument("--deep-scan", action="store_true",
                        help="Ask the model about every chunk, not just those with a "
                             "rule finding. Finds sub-threshold notes anywhere in the "
                             "file; cost then scales with file size, not findings.")
    args = parser.parse_args()

    run(args.input, args.output, args.lines_per_chunk, args.model, args.base_url, LLM_API_KEY,
        compare=args.compare, deep_scan=args.deep_scan)

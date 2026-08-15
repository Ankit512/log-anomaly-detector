#!/usr/bin/env python3
"""
compare.py — the LLM-alone ablation behind `log_analyzer.py --compare`.

The console's headline claim is that N findings "a raw LLM would have
under-rated". This module is what earns that number, or refutes it. It runs the
SAME model over the SAME chunks with a neutral prompt — no detector context, no
pre-flagged anomalies, no instruction to defer on severity — and records what the
model rates each event on its own.

Fairness rules, because a rigged baseline would make the headline worthless:
  - identical chunks, identical model, temperature 0
  - the neutral prompt never mentions rules, thresholds, or pre-flags
  - alignment is generous: when several LLM findings could match a rule finding,
    the HIGHEST-severity one wins, so the baseline gets the benefit of the doubt
  - a chunk the model failed to answer is UNKNOWN, never "missed" — silence
    caused by an off-schema reply is not evidence of a miss

Nothing here changes an authoritative severity. The rule verdict is the finding;
this is annotation beside it.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Neutral: a competent analyst prompt with no knowledge of our rules.
NEUTRAL_SYSTEM_PROMPT = """You are a security log analyst. You are given a chunk of raw log lines.

Identify anomalies, errors, security-relevant events, or operational issues, and assign
each one a severity: "info", "low", "medium", "high", or "critical".

Respond ONLY with valid JSON (no markdown fences, no preamble), matching this schema:

{
  "findings": [
    {
      "severity": "info|low|medium|high|critical",
      "summary": "one sentence describing what happened",
      "evidence": "the specific log line(s) that triggered this finding",
      "reason": "one line on why you chose that severity"
    }
  ]
}

If nothing in the chunk is notable, return an empty "findings" array.
"""

PROMPT_VERSION = "neutral-v1"      # part of the cache key; bump when the prompt changes
CACHE_SCHEMA = "v2"                # bump when the cached entry shape changes

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "missed": 5}

# Statuses whose silence is meaningful. A chunk outside this set tells us nothing
# about the model's judgement, so its findings are UNKNOWN rather than "missed".
USABLE_STATUSES = ("ok", "ok-after-retry")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

CACHE_PATH = Path(__file__).resolve().parent / ".compare_cache.json"


# ---------------------------------------------------------------------------
# The unprimed pass
# ---------------------------------------------------------------------------

def _cache_key(model, temperature, chunk_text):
    h = hashlib.sha256()
    h.update(f"{PROMPT_VERSION}|{CACHE_SCHEMA}|{model}|{temperature}|".encode())
    h.update(chunk_text.encode("utf-8", "replace"))
    return h.hexdigest()


def _load_cache():
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def _save_cache(cache):
    CACHE_PATH.write_text(json.dumps(cache, indent=2))


def run_llm_alone(chunks, chat_fn, model, temperature, strip_fences, use_cache=True):
    """Analyze every chunk with the neutral prompt.

    chat_fn(system, user) -> raw reply text. Injected so this module never
    imports log_analyzer (which imports this one).

    Returns (findings, chunk_status). Status is one of "ok", "ok-after-retry",
    "degraded-empty", "off-schema", "unparseable", "api-error". Only "ok" and
    "ok-after-retry" are evidence of what the model does and does not consider
    notable; anything else means UNKNOWN coverage for that chunk (see
    USABLE_STATUSES).
    """
    cache = _load_cache() if use_cache else {}
    findings, status = [], []
    dirty = False

    for idx, chunk_lines in enumerate(chunks):
        text = "".join(chunk_lines)
        key = _cache_key(model, temperature, text)

        if use_cache and key in cache:
            entry = cache[key]
        else:
            entry = _analyze_one(text, chat_fn, strip_fences)
            if use_cache:
                cache[key] = entry
                dirty = True

        status.append(entry["status"])
        for f in entry.get("findings", []):
            f = dict(f)
            f["chunk_index"] = idx
            findings.append(f)

    if dirty:
        _save_cache(cache)
    return findings, status


def _analyze_one(text, chat_fn, strip_fences):
    prompt = f"Analyze this log chunk:\n\n{text}"
    for attempt in (1, 2):
        try:
            raw = strip_fences(chat_fn(NEUTRAL_SYSTEM_PROMPT, prompt))
        except Exception as e:
            return {"status": "api-error", "detail": str(e)[:120], "findings": []}

        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            if attempt == 2:
                return {"status": "unparseable", "detail": raw[:160], "findings": []}
            prompt = (f"Analyze this log chunk:\n\n{text}\n\nYour previous reply was not "
                      f"valid JSON. Reply with the JSON object only.")
            continue

        if isinstance(obj, dict) and isinstance(obj.get("findings"), list):
            clean = [f for f in obj["findings"]
                     if isinstance(f, dict) and str(f.get("summary", "")).strip()]
            # An empty result that only appeared AFTER a schema nudge is not
            # evidence the model saw nothing. Observed on dense chunks: the first
            # reply lists the events under its own key, the retry then returns
            # {"findings": []}. Silence extracted under duress proves nothing, so
            # it is reported as degraded and excluded from "missed".
            if attempt > 1 and not clean:
                return {"status": "degraded-empty", "findings": [],
                        "detail": "valid schema only after a retry, and empty — "
                                  "cannot distinguish 'nothing notable' from schema failure"}
            return {"status": "ok" if attempt == 1 else "ok-after-retry", "findings": clean}

        if attempt == 2:
            keys = list(obj.keys()) if isinstance(obj, dict) else type(obj).__name__
            return {"status": "off-schema", "detail": f"top-level keys: {keys}", "findings": []}
        prompt = (f"Analyze this log chunk:\n\n{text}\n\nYour previous reply was valid JSON "
                  f'but the wrong shape. Use exactly {{"findings": [...]}} at the top level.')
    return {"status": "off-schema", "findings": []}


# ---------------------------------------------------------------------------
# Alignment
# ---------------------------------------------------------------------------

def _rule_identity(finding):
    """Entities and line numbers that identify what a rule finding is about."""
    ents = finding.get("entities") or {}
    ips = {str(ents[k]) for k in ("ip", "dest_ip") if ents.get(k)}
    host = str(ents["host"]) if ents.get("host") else None
    lines = {e["line"] for e in finding.get("timeline", []) if e.get("line")}
    m = re.search(r"lines (\d+)-(\d+)", finding.get("evidence", "") or "")
    if m:
        lines |= {int(m.group(1)), int(m.group(2))}
    return ips, host, lines


def _llm_identity(llm_finding, records):
    """Entities and line numbers implied by an LLM finding's own words."""
    text = f"{llm_finding.get('summary', '')} {llm_finding.get('evidence', '')}"
    ips = set(IP_RE.findall(text))

    norm = " ".join(text.lower().split())
    lines, hosts = set(), set()
    for r in records:
        msg = " ".join(str(r.get("msg", "")).lower().split())
        if len(msg) >= 24 and msg in norm:
            lines.add(r.get("n"))
            if r.get("host"):
                hosts.add(str(r["host"]))
    for r in records:                       # hosts named directly in the text
        h = str(r.get("host", ""))
        if h and h.lower() in norm:
            hosts.add(h)
    return ips, hosts, lines


def _matches(rule_ids, llm_ids):
    """Same IP, same log line, or same host when neither cites a line.

    Deliberately NOT proximity-based. An earlier version matched line numbers
    within a few lines of each other, which in a short log makes everything
    match everything — and since alignment credits the most severe candidate,
    that silently rated every finding against the loudest thing in the file.
    Exact overlap only.
    """
    r_ips, r_host, r_lines = rule_ids
    l_ips, l_hosts, l_lines = llm_ids

    if r_ips & l_ips:
        return True
    if r_lines & l_lines:
        return True
    if r_host and r_host in l_hosts and not (r_lines and l_lines):
        return True
    return False


def align(rule_findings, llm_findings, records, coverage_ok=True):
    """Annotate each rule finding with the LLM-alone verdict. Mutates in place."""
    llm_ids = [(f, _llm_identity(f, records)) for f in llm_findings]

    for finding in rule_findings:
        rule_ids = _rule_identity(finding)
        candidates = [f for f, ids in llm_ids if _matches(rule_ids, ids)]

        if candidates:
            # Generous: the model's most severe matching call is the one we credit.
            best = min(candidates,
                       key=lambda f: SEVERITY_RANK.get(str(f.get("severity", "info")).lower(), 4))
            llm_sev = str(best.get("severity", "info")).upper()
            why = str(best.get("reason") or best.get("summary") or "").strip()
        elif coverage_ok:
            llm_sev = "MISSED"
            why = "not flagged by the model on its own"
        else:
            llm_sev = "UNKNOWN"
            why = "the model returned no usable output for this chunk — not evidence of a miss"

        rule_rank = SEVERITY_RANK.get(str(finding.get("severity", "info")).lower(), 4)
        llm_rank = SEVERITY_RANK.get(llm_sev.lower(), 5)

        finding["llm_alone_severity"] = llm_sev
        finding["llm_alone_why"] = why
        if llm_sev == "UNKNOWN":
            finding["llm_alone_delta"] = "unknown"
        elif llm_rank > rule_rank:
            finding["llm_alone_delta"] = "under-rated"
        elif llm_rank < rule_rank:
            finding["llm_alone_delta"] = "over-rated"
        else:
            finding["llm_alone_delta"] = "agree"

    return rule_findings


def underrated_count(findings):
    return sum(1 for f in findings if f.get("llm_alone_delta") == "under-rated")

#!/usr/bin/env python3
"""_redact_vendored.py — a self-contained mirror of console/redact.py's masking.

WHY THIS EXISTS
    The MCP server's egress guard (itsoc_mcp/redaction.py) must work even when the
    package is installed STANDALONE (uvx/pipx), with no repo on the path. In that
    case `from console import redact` is unavailable, so redaction.py falls back to
    THIS vendored copy. When the repo IS importable, redaction.py uses the real
    console/redact.py — this file is the fallback, not the primary path.

HONESTY / NO-DRIFT
    The one risk of vendoring is drift: this copy silently diverging from the real
    choke point and masking LESS. That is guarded, not ignored:
      * The masking code below is a VERBATIM copy of console/redact.py — same
        regexes, same Redactor, same order of operations.
      * test_mcp.py runs a DRIFT-GUARD: when the repo is present it asserts this
        vendored masking produces output IDENTICAL to console/redact.py across a
        shared corpus (IPs, usernames, hostnames). If they ever diverge, the test
        fails. When the repo is absent (true standalone), the guard skips with an
        honest note — there is nothing to compare against, and this copy is the
        single source by definition.

    If you edit console/redact.py's masking, mirror the change here (the drift-guard
    will fail until you do).

Stdlib only. Pure functions, no I/O.
"""

import re

MAX_LINE_CHARS = 2000                 # a "line" longer than this is not a log line

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Conservative IPv6: hex groups with at least two ':' separators (avoids MACs and times).
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")

# Username positions in the vocabularies this project actually parses:
#   canonical  "auth failed for user 'admin' from ..."
#   sshd       "Failed password for invalid user admin from ..."
#              "Accepted publickey for ankit from ..."
#   pam        "... user=root"
USER_PATTERNS = [
    re.compile(r"(?<=user ')(?P<u>[^']+)(?=')"),
    # Finding titles quote the principal without the word "user":
    #   "Brute-force then SUCCESSFUL login for 'admin' from ..."
    re.compile(r"(?<=for ')(?P<u>[^']+)(?=')"),
    re.compile(r"\b(?:Failed|Accepted)\s+\S+\s+for\s+(?:invalid user\s+)?(?P<u>[A-Za-z0-9._$-]+)"),
    re.compile(r"\bfor user\s+(?P<u>[A-Za-z0-9._$-]+)"),
    re.compile(r"\buser=(?P<u>[A-Za-z0-9._$-]+)"),
    re.compile(r"\binvalid user\s+(?P<u>[A-Za-z0-9._$-]+)"),
]

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class Redactor:
    """One redaction scope: the same value maps to the same placeholder for the
    lifetime of this object, so a set of lines stays internally consistent."""

    def __init__(self, hosts=(), users=()):
        self.mapping = {}              # real value -> placeholder
        self.counts = {"IP": 0, "USER": 0, "HOST": 0}
        # Longest first, so "app-01.internal" wins over "app-01".
        self.hosts = sorted({h for h in hosts if h and h != "—"}, key=len, reverse=True)
        self.users = sorted({u for u in users if u}, key=len, reverse=True)

    def _mask(self, kind, value):
        if value not in self.mapping:
            self.counts[kind] += 1
            self.mapping[value] = f"[{kind}-{self.counts[kind]}]"
        return self.mapping[value]

    def redact(self, text):
        """Sanitize + mask one string. Order matters: IPs first (so username
        patterns never latch onto an already-masked token), then known names."""
        text = _CONTROL_RE.sub("", text)[:MAX_LINE_CHARS]
        text = IPV4_RE.sub(lambda m: self._mask("IP", m.group(0)), text)
        text = IPV6_RE.sub(lambda m: self._mask("IP", m.group(0)), text)
        for pat in USER_PATTERNS:
            text = pat.sub(lambda m: m.group(0).replace(m.group("u"), self._mask("USER", m.group("u"))), text)
        for user in self.users:
            text = re.sub(rf"\b{re.escape(user)}\b",
                          lambda m: self._mask("USER", m.group(0)), text)
        for host in self.hosts:
            text = re.sub(rf"\b{re.escape(host)}\b",
                          lambda m: self._mask("HOST", m.group(0)), text)
        return text

    def redact_lines(self, lines):
        return [self.redact(line) for line in lines]


def redact_lines(lines, hosts=(), users=()):
    """Mask a list of lines in one shared scope. Returns (redacted, redactor)."""
    r = Redactor(hosts=hosts, users=users)
    return r.redact_lines(lines), r


def redact_text(text, hosts=(), users=()):
    """Mask one string. Convenience wrapper over a fresh scope."""
    return Redactor(hosts=hosts, users=users).redact(text)

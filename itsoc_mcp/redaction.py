"""redaction.py — the egress guard for anything leaving this MCP server.

An MCP client may be a cloud agent, so raw log text must NOT leave by default.
Every field that can carry raw log lines passes through the project's existing
choke point (console/redact.py — the SAME masking the remote-compute path uses)
before it is returned, UNLESS the operator explicitly opts out for a trusted
local session by setting ITSOC_MCP_TRUSTED_LOCAL=1.

This module does NOT reimplement masking — it delegates to console.redact so
there is one masking implementation in the project, not two that can drift.
"""

import os
import sys
from pathlib import Path

# console/redact.py lives at the repo root's `console` package. When this server
# is launched as `python -m itsoc_mcp` from the repo root, the root is already on
# sys.path; add it defensively so redaction never silently fails to import (which
# would be the one failure mode we must never have — leaking unredacted text).
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from console import redact as _redact   # noqa: E402  (path set up above)

TRUSTED_ENV = "ITSOC_MCP_TRUSTED_LOCAL"


def trusted_local():
    """True only when the operator has explicitly opted into returning raw text."""
    return os.environ.get(TRUSTED_ENV, "").strip() in ("1", "true", "TRUE", "yes", "on")


def redaction_mode():
    """The string surfaced in the provenance block of every response."""
    return "off (ITSOC_MCP_TRUSTED_LOCAL=1)" if trusted_local() else "on"


def redact_lines(lines, hosts=(), users=()):
    """Mask a list of log lines in one shared scope. Pass-through only when the
    trusted-local opt-out is set. Returns a plain list of strings."""
    lines = [("" if line is None else str(line)) for line in (lines or [])]
    if trusted_local():
        return lines
    masked, _r = _redact.redact_lines(lines, hosts=hosts, users=users)
    return masked


def redact_text(text, hosts=(), users=()):
    """Mask one string unless the trusted-local opt-out is set."""
    text = "" if text is None else str(text)
    if trusted_local():
        return text
    return _redact.redact_text(text, hosts=hosts, users=users)


def redact_batch(strings, hosts=(), users=()):
    """Mask several strings in ONE shared scope, so the same value maps to the
    same placeholder across all of them (e.g. an IP in an evidence line and in a
    timeline label both become [IP-1]). Pass-through only with the trusted-local
    opt-out. Returns a list of strings, same length/order as the input."""
    strings = [("" if s is None else str(s)) for s in (strings or [])]
    if trusted_local():
        return strings
    r = _redact.Redactor(hosts=hosts, users=users)
    return [r.redact(s) for s in strings]

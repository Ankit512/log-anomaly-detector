"""redaction.py — the egress guard for anything leaving this MCP server.

An MCP client may be a cloud agent, so raw log text must NOT leave by default.
Every field that can carry raw log lines passes through the project's masking
choke point before it is returned, UNLESS the operator explicitly opts out for a
trusted local session by setting ITSOC_MCP_TRUSTED_LOCAL=1.

SINGLE SOURCE OF TRUTH, WITH A SAFE FALLBACK
    In the repo, this delegates to console/redact.py — the SAME masking the
    remote-compute path uses — so there is one implementation, not two that can
    drift. When the package is installed STANDALONE (uvx/pipx, no repo on path),
    console/redact.py is not importable, so it falls back to a VERBATIM vendored
    mirror (itsoc_mcp/_redact_vendored.py). The fallback keeps the guard exactly
    as strong standalone as in-repo; a drift-guard test asserts the two never
    diverge (see test_mcp.py). We NEVER silently ship a weaker masker: if neither
    import succeeds, module import fails loudly rather than passing text through.
"""

import os
import sys
from pathlib import Path

# When launched as `python -m itsoc_mcp` from the repo root the root is already on
# sys.path; add it defensively so the in-repo path (single source of truth) is
# preferred whenever the repo is actually present.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Prefer the repo's choke point; fall back to the vendored mirror when standalone.
# `_redact_source` names which is active (surfaced to the drift-guard test).
try:
    from console import redact as _redact   # noqa: E402  (path set up above)
    _redact_source = "console.redact"
except ImportError:
    from . import _redact_vendored as _redact  # noqa: E402
    _redact_source = "itsoc_mcp._redact_vendored"


def redact_source():
    """Which masking implementation is active: 'console.redact' in-repo, or the
    vendored mirror when installed standalone. Behaviour is identical either way."""
    return _redact_source


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

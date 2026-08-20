"""threat_intel_offline.py — the OFFLINE STIX->MITRE lookup path.

This reuses the project's EXISTING offline threat-intel code (threat_intel/) —
it does not reimplement matching or invent severities:
  * taxii_client.extract_iocs / extract_technique_refs parse a local STIX bundle,
  * threat_detector.match_and_enrich / severity_for do the deterministic match +
    severity (rule-owned, not guessed here),
  * mitre_attack.MitreAttackMapper resolves technique STIX ids to names/tactics.

Everything here is offline and network-free: it reads a local STIX bundle (path
from ITSOC_STIX_BUNDLE) and the locally-cached ATT&CK database. Nothing leaves
the machine. If no bundle is configured, the honest answer is "n/a — nothing to
match against", never a fabricated verdict; if the ATT&CK cache is absent, IOC
matches are still reported but technique names are marked unavailable.

STANDALONE INSTALL: this path reuses the repo's sibling threat_intel/ package. In
a bare `uvx itsoc-mcp` install that directory is not shipped, so the whole path is
unavailable. That is surfaced as ThreatIntelUnavailable and the tool FAILS CLOSED
with an honest message — never a fabricated match or a fake all-clear.
"""

import os
import re
import sys
from pathlib import Path

STIX_BUNDLE_ENV = "ITSOC_STIX_BUNDLE"
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

# The threat_intel package is a set of sibling scripts that import each other by
# bare name (`import mitre_attack`), so its own directory must be on sys.path.
_THREAT_DIR = Path(__file__).resolve().parent.parent / "threat_intel"

UNAVAILABLE_MSG = (
    "offline threat-intel is unavailable in this install: the repo's threat_intel/ "
    "package is not on the path (expected in a standalone `uvx itsoc-mcp` install). "
    "This is NOT a clean verdict and NOT an all-clear on the IP — run the MCP server "
    "from the repo (python -m itsoc_mcp) to use offline threat-intel."
)


class ThreatIntelUnavailable(Exception):
    """Raised when the sibling threat_intel/ package is not importable (standalone
    install). Callers translate this into an honest fail-closed tool response."""


def threat_intel_available():
    """True only when the sibling threat_intel/ modules can actually be imported."""
    if not _THREAT_DIR.is_dir():
        return False
    _ensure_path()
    try:
        import threat_detector  # noqa: F401
        import taxii_client     # noqa: F401
        return True
    except Exception:
        return False


def _require_available():
    if not threat_intel_available():
        raise ThreatIntelUnavailable(UNAVAILABLE_MSG)


def _ensure_path():
    if _THREAT_DIR.is_dir() and str(_THREAT_DIR) not in sys.path:
        sys.path.insert(0, str(_THREAT_DIR))


class _NullMapper:
    """Stands in for MitreAttackMapper when the ATT&CK cache is not present, so
    matching still works but yields no technique names (honestly empty, never
    fabricated)."""

    def lookup_by_stix_id(self, _stix_id):
        return None


def is_ipv4(value):
    if not _IPV4_RE.match(value or ""):
        return False
    return all(0 <= int(o) <= 255 for o in value.split("."))


def bundle_path(override=None):
    p = override or os.environ.get(STIX_BUNDLE_ENV)
    return p.strip() if p else None


def build_mapper():
    """Return (mapper, note). `mapper` resolves technique ids; when the ATT&CK
    cache is missing it is a _NullMapper and `note` explains the degradation."""
    _require_available()
    _ensure_path()
    try:
        import mitre_attack
        return mitre_attack.MitreAttackMapper(offline=True), None
    except FileNotFoundError:
        return (_NullMapper(),
                "MITRE ATT&CK database not cached locally — technique names "
                "unavailable (run threat_intel with network once to populate). "
                "IOC matching still applies.")
    except Exception as e:                       # pragma: no cover - defensive
        return _NullMapper(), f"MITRE mapper unavailable: {e}"


def load_objects(path):
    """Load STIX objects from a local bundle. Raises FileNotFoundError/ValueError
    honestly; callers translate that into an honest tool error."""
    _require_available()
    _ensure_path()
    import threat_detector
    return threat_detector.load_stix_objects_offline(path)


def match_ip(ip, objects, mapper):
    """Deterministic match of one IP against the bundle's indicators, enriched
    with ATT&CK context. Pure reuse of the existing offline functions. Returns a
    list of match dicts (possibly empty — an honest 'no match')."""
    _require_available()
    _ensure_path()
    import taxii_client
    import threat_detector

    threat_iocs = taxii_client.extract_iocs(objects)
    technique_links = taxii_client.extract_technique_refs(objects)
    observed = {"ipv4": {ip}}
    return threat_detector.match_and_enrich(observed, threat_iocs, technique_links, mapper)

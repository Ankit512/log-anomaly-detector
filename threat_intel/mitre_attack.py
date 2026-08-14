#!/usr/bin/env python3
"""
mitre_attack.py — Loads the official MITRE ATT&CK Enterprise STIX bundle and
builds a lookup so any STIX "attack-pattern" reference (or raw technique ID
like "T1110" or "T1110.001") can be resolved to its name, tactic(s), and
description.

Source: https://github.com/mitre/cti (MITRE's official STIX 2.1 ATT&CK data)

This is used by threat_detector.py to turn TAXII threat-intel matches into
human-readable ATT&CK context (e.g. "T1110 - Brute Force / Credential
Access") instead of a bare technique ID.

Usage as a library:
    from mitre_attack import MitreAttackMapper
    mapper = MitreAttackMapper()          # downloads + caches locally
    mapper.lookup("T1110")                # -> dict with name/tactics/url
    mapper.lookup_by_stix_id("attack-pattern--...")

Usage standalone (sanity check / cache refresh):
    python mitre_attack.py --refresh
    python mitre_attack.py --technique T1110
"""

import argparse
import json
import os
import urllib.request
from pathlib import Path

ATTACK_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
DEFAULT_CACHE_PATH = Path.home() / ".cache" / "mitre_attack" / "enterprise-attack.json"


class MitreAttackMapper:
    def __init__(self, cache_path: Path = DEFAULT_CACHE_PATH, offline: bool = False):
        self.cache_path = Path(cache_path)
        self._by_technique_id = {}     # "T1110" -> record
        self._by_stix_id = {}          # "attack-pattern--uuid" -> record
        self._tactics_by_shortname = {}  # "credential-access" -> "Credential Access"
        self._load(offline=offline)

    # ------------------------------------------------------------------
    def _load(self, offline: bool):
        if not self.cache_path.exists():
            if offline:
                raise FileNotFoundError(
                    f"No cached ATT&CK data at {self.cache_path} and offline=True. "
                    f"Run once with network access to populate the cache."
                )
            self._download()
        with open(self.cache_path, "r") as f:
            bundle = json.load(f)
        self._index(bundle)

    def _download(self):
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(ATTACK_BUNDLE_URL, headers={"User-Agent": "threat-detector/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
        with open(self.cache_path, "wb") as f:
            f.write(data)

    def _index(self, bundle: dict):
        objects = bundle.get("objects", [])

        # First pass: tactics (x-mitre-tactic) so we can resolve kill_chain_phases
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                shortname = obj.get("x_mitre_shortname")
                if shortname:
                    self._tactics_by_shortname[shortname] = obj.get("name", shortname)

        # Second pass: attack-pattern (techniques)
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            technique_id = None
            url = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    url = ref.get("url")
                    break
            if not technique_id:
                continue

            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    shortname = phase.get("phase_name")
                    tactics.append(self._tactics_by_shortname.get(shortname, shortname))

            record = {
                "technique_id": technique_id,
                "name": obj.get("name"),
                "tactics": tactics,
                "description": (obj.get("description") or "")[:400],
                "url": url,
                "stix_id": obj.get("id"),
                "platforms": obj.get("x_mitre_platforms", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            }
            self._by_technique_id[technique_id] = record
            self._by_stix_id[obj.get("id")] = record

    # ------------------------------------------------------------------
    def lookup(self, technique_id: str):
        """Look up by ATT&CK technique ID, e.g. 'T1110' or 'T1110.001'."""
        return self._by_technique_id.get(technique_id.upper())

    def lookup_by_stix_id(self, stix_id: str):
        """Look up by raw STIX object id, e.g. 'attack-pattern--...'."""
        return self._by_stix_id.get(stix_id)

    def technique_count(self):
        return len(self._by_technique_id)

    def refresh(self):
        self._download()
        with open(self.cache_path, "r") as f:
            bundle = json.load(f)
        self._by_technique_id.clear()
        self._by_stix_id.clear()
        self._tactics_by_shortname.clear()
        self._index(bundle)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MITRE ATT&CK STIX mapper — sanity check / cache tool")
    parser.add_argument("--refresh", action="store_true", help="Force re-download the ATT&CK bundle")
    parser.add_argument("--technique", help="Look up a technique ID, e.g. T1110")
    args = parser.parse_args()

    mapper = MitreAttackMapper()
    if args.refresh:
        print("Refreshing MITRE ATT&CK cache...")
        mapper.refresh()

    print(f"Loaded {mapper.technique_count()} techniques.")

    if args.technique:
        rec = mapper.lookup(args.technique)
        if rec:
            print(json.dumps(rec, indent=2))
        else:
            print(f"Technique {args.technique} not found.")

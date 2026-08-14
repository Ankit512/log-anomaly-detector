#!/usr/bin/env python3
"""
taxii_client.py — Thin wrapper around taxii2-client + stix2 for pulling
threat-intel objects (indicators, malware, attack-patterns, relationships)
from a TAXII 2.0/2.1 server.

This does NOT hardcode any specific feed. Point it at whatever TAXII server
your org has access to (commercial feed, ISAC/ISAO, MISP-TAXII bridge,
OpenCTI, Anomali, etc.) via config or CLI args.

Usage as a library:
    from taxii_client import TaxiiFeed

    feed = TaxiiFeed(
        discovery_url="https://your-taxii-server.example.com/taxii2/",
        collection_id="collection-uuid",
        username="user", password="pass",   # or api_key=... depending on server
    )
    for stix_obj in feed.pull_objects(added_after="2026-08-01T00:00:00Z"):
        ...

Usage standalone (list collections on a server, or dump recent indicators):
    python taxii_client.py --discovery-url https://host/taxii2/ --list-collections
    python taxii_client.py --discovery-url https://host/taxii2/ --collection-id XXX --dump indicators.json
"""

import argparse
import json
import sys

# taxii2client is needed ONLY for live TAXII pulls (TaxiiFeed). The pure-STIX
# helpers below — extract_iocs / extract_technique_refs — are stdlib-only and are
# what offline --stix-bundle mode uses, so a missing package must not stop this
# module importing. TaxiiFeed raises a clear install hint instead.
TAXII_AVAILABLE = True
try:
    from taxii2client.v21 import Server, as_pages
except ImportError:
    try:
        # Fall back to 2.0 client if the server only speaks TAXII 2.0
        from taxii2client.v20 import Server, as_pages
    except ImportError:
        Server = None
        as_pages = None
        TAXII_AVAILABLE = False


class TaxiiFeed:
    def __init__(self, discovery_url, collection_id=None, username=None,
                 password=None, verify_ssl=True):
        if not TAXII_AVAILABLE:
            raise RuntimeError(
                "Live TAXII mode requires the taxii2client package, which is not "
                "installed. Install it with:  pip install -r requirements-taxii.txt\n"
                "Offline mode needs no extra packages — use --stix-bundle instead."
            )
        self.discovery_url = discovery_url
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.server = Server(
            discovery_url,
            user=username,
            password=password,
            verify=verify_ssl,
        )
        self.collection_id = collection_id
        self._collection = None

    # ------------------------------------------------------------------
    def list_collections(self):
        """Return [(api_root_url, collection_id, title, description), ...]
        across all API roots the server exposes."""
        results = []
        for api_root in self.server.api_roots:
            for coll in api_root.collections:
                results.append({
                    "api_root": api_root.url,
                    "collection_id": coll.id,
                    "title": coll.title,
                    "description": getattr(coll, "description", ""),
                })
        return results

    def _get_collection(self):
        if self._collection is not None:
            return self._collection
        if not self.collection_id:
            raise ValueError("collection_id is required to pull objects")
        for api_root in self.server.api_roots:
            for coll in api_root.collections:
                if coll.id == self.collection_id:
                    from taxii2client.v21 import Collection
                    self._collection = Collection(
                        f"{api_root.url}collections/{coll.id}/",
                        user=self.username,
                        password=self.password,
                        verify=self.verify_ssl,
                    )
                    return self._collection
        raise ValueError(f"Collection {self.collection_id} not found on this server")

    def pull_objects(self, added_after=None, obj_type=None, limit_per_page=100):
        """Generator yielding raw STIX object dicts (indicator, malware,
        attack-pattern, relationship, etc.) from the configured collection.
        Paginates automatically."""
        collection = self._get_collection()
        kwargs = {}
        if added_after:
            kwargs["added_after"] = added_after
        if obj_type:
            kwargs["type"] = obj_type

        for bundle in as_pages(collection.get_objects, per_request=limit_per_page, **kwargs):
            for obj in bundle.get("objects", []):
                yield obj


def extract_iocs(stix_objects):
    """Given a list of raw STIX 'indicator' objects, extract a flat list of
    (ioc_type, value, stix_id, indicator_pattern) tuples for simple IP/domain/
    hash/url matching against your own logs.

    Handles common STIX pattern shapes like:
        [ipv4-addr:value = '1.2.3.4']
        [domain-name:value = 'evil.example.com']
        [file:hashes.'SHA-256' = 'abcd...']
        [url:value = 'http://evil.example.com/payload']
    """
    import re
    patterns = {
        "ipv4": re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'"),
        "ipv6": re.compile(r"ipv6-addr:value\s*=\s*'([^']+)'"),
        "domain": re.compile(r"domain-name:value\s*=\s*'([^']+)'"),
        "url": re.compile(r"url:value\s*=\s*'([^']+)'"),
        "sha256": re.compile(r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'"),
        "md5": re.compile(r"file:hashes\.'MD5'\s*=\s*'([^']+)'"),
    }

    iocs = []
    for obj in stix_objects:
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        for ioc_type, regex in patterns.items():
            for match in regex.findall(pattern):
                iocs.append({
                    "ioc_type": ioc_type,
                    "value": match,
                    "stix_id": obj.get("id"),
                    "name": obj.get("name", ""),
                    "labels": obj.get("indicator_types", obj.get("labels", [])),
                    "valid_from": obj.get("valid_from"),
                })
    return iocs


def extract_technique_refs(stix_objects):
    """Given raw STIX objects (indicators, malware, relationships, attack-patterns),
    find links from indicators -> attack-patterns via 'relationship' objects
    (relationship_type == 'indicates') so we know which ATT&CK technique an
    indicator maps to.

    Returns: dict of indicator_stix_id -> [attack_pattern_stix_id, ...]
    """
    links = {}
    for obj in stix_objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "indicates":
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        if src.startswith("indicator--") and tgt.startswith("attack-pattern--"):
            links.setdefault(src, []).append(tgt)
    return links


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TAXII 2.x feed client")
    parser.add_argument("--discovery-url", required=True, help="TAXII server discovery URL")
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--collection-id", default=None)
    parser.add_argument("--list-collections", action="store_true")
    parser.add_argument("--dump", default=None, help="Pull objects and write raw STIX JSON to this file")
    parser.add_argument("--no-verify-ssl", action="store_true")
    args = parser.parse_args()

    feed = TaxiiFeed(
        discovery_url=args.discovery_url,
        collection_id=args.collection_id,
        username=args.username,
        password=args.password,
        verify_ssl=not args.no_verify_ssl,
    )

    if args.list_collections:
        for c in feed.list_collections():
            print(f"{c['collection_id']}  {c['title']}  ({c['api_root']})")
        sys.exit(0)

    if args.dump:
        if not args.collection_id:
            print("ERROR: --collection-id is required to pull objects")
            sys.exit(1)
        objects = list(feed.pull_objects())
        with open(args.dump, "w") as f:
            json.dump(objects, f, indent=2)
        print(f"Wrote {len(objects)} STIX objects to {args.dump}")

# Threat-intel enrichment (Stage C prototype)

A **downstream, opt-in** step that takes the analyzer's flagged IPs, matches them
against threat-intel indicators, and resolves each match to a MITRE ATT&CK
technique. It turns *"outbound connection to 45.153.160.2:4444 blocked"* into
*"T1071 Application Layer Protocol — Command and Control, known C2 IP."*

**Nothing here is wired into the core pipeline.** `log_analyzer.py` and
`anomaly_detector.py` are untouched and stay read-only and fully local; this step
reads their output afterwards. Offline mode is the default and needs no packages
beyond the Python standard library.

## The demo, end to end

Run from the repo root. Offline — no TAXII server, no `taxii2client`:

```bash
python3 log_analyzer.py --input sample-2.log --output demo_report
python3 threat_intel/export_iocs.py demo_report.json > demo_iocs.txt
python3 threat_intel/threat_detector.py --input demo_iocs.txt \
    --stix-bundle threat_intel/demo_threat_intel.json --output demo_threat_report
```

Expected result — 2 matches, both CRITICAL:

| Observed IOC | Matched indicator | MITRE ATT&CK |
|---|---|---|
| `203.0.113.44` | Known brute-force source IP | **T1110** — Brute Force (Credential Access) |
| `45.153.160.2` | Known C2 callback IP | **T1071** — Application Layer Protocol (Command and Control) |

The first run downloads MITRE's ATT&CK bundle (~46 MB) to
`~/.cache/mitre_attack/`. Every later run is offline. Nothing refreshes that cache
automatically — re-run `python3 threat_intel/mitre_attack.py --refresh` when you
want current technique data.

Demo outputs (`demo_report.*`, `demo_iocs.txt`, `demo_threat_report.*`) are
gitignored; the commands above regenerate them.

## Smoke test

```bash
python3 threat_intel/test_threat_intel.py    # non-zero exit on failure
```

Network-free. It asserts IOC extraction and matching against the local demo
bundle. Technique resolution is a **bonus** check: with a warm ATT&CK cache it
verifies T1110/T1071; with a cold cache it reports `[SKIP]` and still passes,
rather than downloading 46 MB inside a test.

## Files

| File | Role |
|---|---|
| `export_iocs.py` | Reads the analyzer's `report.json` and emits a clean IOC list from each finding's `entities`. **Stdlib.** |
| `threat_detector.py` | Matches observed IOCs against threat intel, resolves ATT&CK, writes JSON + Markdown. |
| `taxii_client.py` | Live TAXII 2.x pull **plus** the stdlib STIX helpers (`extract_iocs`, `extract_technique_refs`) that offline mode uses. |
| `mitre_attack.py` | Downloads/caches MITRE ATT&CK and resolves technique IDs. **Stdlib** (`urllib`). |
| `demo_threat_intel.json` | Tiny local STIX bundle: 3 indicators, 2 ATT&CK relationships. |
| `test_threat_intel.py` | Network-free smoke test. |
| `requirements-taxii.txt` | **Live TAXII only.** Not needed offline. |

## Why an exporter instead of `--export-flagged`

`threat_detector.py`'s docstring describes a pipeline built on
`anomaly_detector.py --export-flagged`. That flag never existed in our validated
detector — it belonged to a rejected prototype. `export_iocs.py` replaces it from
the other end, reading the `entities` the analyzer already records, so the
validated detector needs no changes.

It reads entity keys in the order `ip → dest_ip → host`, matching `entity_of()` in
`tests/eval/run_eval.py`. Keep the two in step if either changes.

Exporting from `entities` rather than grepping the raw log matters: the IOC regexes
in `threat_detector.py` are deliberately permissive, so scanning a whole log
harvests every IP that appears anywhere. Only rule-flagged principals get exported
here.

`--ips-only` omits internal hostnames (a `critical_service_event` on `server-03`
exports `server-03`, which is your own asset name, not an indicator). Use it before
sending anything to a live or third-party feed.

## Live TAXII mode (not enabled)

```bash
pip install -r threat_intel/requirements-taxii.txt
python3 threat_intel/threat_detector.py --input demo_iocs.txt \
    --taxii-discovery-url https://your-taxii-server/taxii2/ \
    --taxii-collection-id COLLECTION_UUID \
    --taxii-username user --taxii-password pass \
    --output threat_report
```

Untested here, and a deliberate decision rather than a default: **live mode sends
your observed IOCs to a third party.** The project's constraint is that log data
stays local, so offline `--stix-bundle` is the supported path. Without
`taxii2client` installed, `TaxiiFeed` raises a clear install hint and the offline
path is unaffected.

## Known follow-ups (not addressed)

- **`severity_for()` flattens priority.** Any `malicious-activity` label plus any
  technique yields `critical`, so both demo matches rate CRITICAL. Fine at three
  indicators; useless at three thousand. Needs a real ranking before production.
- **Live TAXII is unwired and untested** — no server has been exercised, and the
  credential flow (`--taxii-password` on the command line) conflicts with the
  project's certificate/token-only principle. Revisit under T9.
- **`DOMAIN_RE` is permissive.** Feeding a raw log rather than an exported IOC list
  will extract noisy pseudo-domains. Another reason to use `export_iocs.py`.
- **ATT&CK cache never auto-refreshes**, and `offline=True` raises on a cold cache.

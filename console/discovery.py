"""Network discovery + vulnerability scan (socf-discovery).

A *sibling* subsystem for the SOC Command Center: it drives real ``nmap`` via a
subprocess, parses its ``-oX`` XML, and writes the results to the persistent
store (``store.insert_asset`` / ``store.insert_vuln``) per the contract in
``docs/soc_command_center.md``. Results are then read back through the existing
``/api/store/assets`` and ``/api/store/vulns`` endpoints.

Honesty / safety posture (this is a dual-use tool):

* **Authorized targets only.** ``authorized_target()`` allows *only*
  RFC1918/private, loopback, or link-local addresses (single hosts, CIDR
  ranges) and hostnames that resolve *entirely* to such addresses. Public or
  routable targets — and hostnames that resolve to any public IP — are refused.
* **Never auto-scan.** Every scan is user-initiated from the UI; nothing here
  runs a scan on its own or on a timer.
* **Only real output is stored.** If ``nmap`` is not installed we return an
  honest error ("network discovery needs nmap installed") — never a simulated
  or fabricated result. An empty scan stores nothing and shows an empty state.
* **Severity is source-reported, not guessed.** A vulnerability's severity is
  derived from the NSE-reported CVSS score (the standard CVSS band); when NSE
  reports no CVSS the severity is left empty (honest "unknown"). We never
  keyword-guess a severity.

Stdlib + subprocess only (no new Python deps; ``nmap`` is an external binary).
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import store

NMAP_ABSENT_MSG = "network discovery needs nmap installed"
UNAUTHORIZED_MSG = "only private/authorized targets may be scanned"

# A CVE id and (optionally) an adjacent CVSS score, as printed by NSE scripts
# such as `vulners` (e.g. "CVE-2021-3618    7.4   https://...").
_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)
_CVE_CVSS_RE = re.compile(
    r"(CVE-\d{4}-\d{3,7})\s+(\d{1,2}(?:\.\d)?)", re.IGNORECASE)


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Authorization gate — the single decision on whether a target may be scanned.
# ---------------------------------------------------------------------------

def _is_private_ip(ip: ipaddress._BaseAddress) -> bool:
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local)


def authorized_target(target: str) -> bool:
    """True only if *target* is a private/loopback/link-local host or range.

    Accepts a single IP, a CIDR network, or a hostname. A hostname is allowed
    only when it resolves and *every* resolved address is private — a hostname
    that resolves to any public/routable IP is refused. Anything unparseable or
    unresolvable is refused.
    """
    if not target or not isinstance(target, str):
        return False
    target = target.strip()
    if not target:
        return False

    # A CIDR network or bare IP: decide directly, no DNS.
    try:
        net = ipaddress.ip_network(target, strict=False)
        return _is_private_ip(net)
    except ValueError:
        pass
    try:
        return _is_private_ip(ipaddress.ip_address(target))
    except ValueError:
        pass

    # Otherwise treat it as a hostname: it is authorized only if it resolves
    # and *all* resolved addresses are private (a public answer disqualifies it).
    try:
        infos = socket.getaddrinfo(target, None)
    except (socket.gaierror, socket.error, UnicodeError):
        return False
    addrs = {info[4][0] for info in infos}
    if not addrs:
        return False
    for addr in addrs:
        try:
            if not _is_private_ip(ipaddress.ip_address(addr)):
                return False
        except ValueError:
            return False
    return True


def nmap_path():
    """Absolute path to the nmap binary, or None if it is not installed."""
    return shutil.which("nmap")


# ---------------------------------------------------------------------------
# XML parsing — turn nmap -oX output into asset/vuln records for the store.
# ---------------------------------------------------------------------------

def _severity_from_cvss(cvss: float) -> str:
    """Standard CVSS band. Empty string when there is no score to band."""
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    if cvss > 0:
        return "LOW"
    return ""


def _vulns_from_script(ip: str, script_id: str, output: str):
    """Extract vulnerability records from one NSE <script> output block.

    Prefers explicit CVE+CVSS pairs (severity from the NSE-reported CVSS band).
    Falls back to bare CVE ids with an empty severity (honest unknown). If the
    script reported neither a CVE nor an explicit VULNERABLE state, nothing is
    emitted — we do not manufacture a finding.
    """
    out = output or ""
    records = []
    seen = set()

    for cve, cvss_text in _CVE_CVSS_RE.findall(out):
        cve = cve.upper()
        if cve in seen:
            continue
        seen.add(cve)
        try:
            cvss = float(cvss_text)
        except ValueError:
            cvss = 0.0
        records.append({
            "asset_ip": ip, "name": script_id, "cve": cve,
            "severity": _severity_from_cvss(cvss), "cvss": cvss,
            "details": out.strip()[:2000], "source": "nmap:" + script_id,
            "status": "OPEN",
        })

    # Bare CVEs with no adjacent CVSS: record with empty (unknown) severity.
    for cve in _CVE_RE.findall(out):
        cve = cve.upper()
        if cve in seen:
            continue
        seen.add(cve)
        records.append({
            "asset_ip": ip, "name": script_id, "cve": cve, "severity": "",
            "cvss": 0.0, "details": out.strip()[:2000],
            "source": "nmap:" + script_id, "status": "OPEN",
        })

    # No CVE at all, but the script asserts a VULNERABLE state: keep it, with an
    # empty severity because NSE gave us no score to band.
    if not records and "VULNERABLE" in out.upper():
        records.append({
            "asset_ip": ip, "name": script_id, "cve": "", "severity": "",
            "cvss": 0.0, "details": out.strip()[:2000],
            "source": "nmap:" + script_id, "status": "OPEN",
        })
    return records


def parse_nmap_xml(xml_text: str):
    """Parse nmap -oX XML into (assets, vulns) record lists.

    Only hosts nmap reports as *up* become assets. Raises ET.ParseError on
    malformed XML (the caller turns that into an honest error).
    """
    root = ET.fromstring(xml_text)
    assets, vulns = [], []
    for h in root.findall("host"):
        status_el = h.find("status")
        state = status_el.attrib.get("state", "") if status_el is not None else ""
        if state and state != "up":
            continue

        ip = mac = vendor = hostname = os_name = ""
        for a in h.findall("address"):
            kind = a.attrib.get("addrtype", "")
            if kind in ("ipv4", "ipv6") and not ip:
                ip = a.attrib.get("addr", "")
            elif kind == "mac":
                mac = a.attrib.get("addr", "")
                vendor = a.attrib.get("vendor", "")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.attrib.get("name", "")
        osm = h.find("os/osmatch")
        if osm is not None:
            os_name = osm.attrib.get("name", "")

        ports = []
        for port in h.findall("ports/port"):
            st = port.find("state")
            if st is None or st.attrib.get("state") != "open":
                continue
            svc = port.find("service")
            svc_name = svc.attrib.get("name", "") if svc is not None else ""
            svc_ver = ""
            if svc is not None:
                svc_ver = " ".join(
                    x for x in (svc.attrib.get("product", ""),
                                svc.attrib.get("version", "")) if x).strip()
            label = f"{port.attrib.get('portid', '')}/{port.attrib.get('protocol', '')}"
            if svc_name:
                label += ":" + svc_name
            if svc_ver:
                label += f" ({svc_ver})"
            ports.append(label)

            for sc in port.findall("script"):
                vulns.extend(_vulns_from_script(
                    ip, sc.attrib.get("id", "script"), sc.attrib.get("output", "")))

        # Host-level scripts (some vuln scripts attach to the host, not a port).
        for sc in h.findall("hostscript/script"):
            vulns.extend(_vulns_from_script(
                ip, sc.attrib.get("id", "script"), sc.attrib.get("output", "")))

        assets.append({
            "ip": ip, "hostname": hostname, "mac": mac, "vendor": vendor,
            "os": os_name, "ports": ", ".join(ports), "source": "nmap",
            "status": "up",
        })
    return assets, vulns


# ---------------------------------------------------------------------------
# Scanner — one at a time, run in a background thread so the request returns
# immediately and the UI polls status(). Results land in the store.
# ---------------------------------------------------------------------------

class DiscoveryScanner:
    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self.running = False
        self.target = ""
        self.vuln = False
        self.started_at = None
        self.finished_at = None
        self.error = ""
        self.hosts_found = 0
        self.assets_stored = 0
        self.vulns_stored = 0

    def status(self):
        with self._lock:
            return {
                "running": self.running,
                "target": self.target,
                "vuln": self.vuln,
                "startedAt": self.started_at,
                "finishedAt": self.finished_at,
                "error": self.error,
                "hostsFound": self.hosts_found,
                "assetsStored": self.assets_stored,
                "vulnsStored": self.vulns_stored,
                "nmapInstalled": nmap_path() is not None,
            }

    def start(self, target: str, vuln: bool = False):
        """Validate and launch a scan. Returns (status_dict, http_code).

        The authorization gate and the nmap-present check happen here so the
        HTTP layer can surface the right code (400 refused / 400 nmap-absent /
        409 already-running) with an honest message.
        """
        target = (target or "").strip()
        if not target:
            return {"error": "a target host or CIDR is required"}, 400
        if not authorized_target(target):
            return {"error": UNAUTHORIZED_MSG, "target": target}, 400
        if nmap_path() is None:
            return {"error": NMAP_ABSENT_MSG}, 400

        with self._lock:
            if self.running:
                return {"error": "a scan is already running",
                        "target": self.target}, 409
            self.running = True
            self.target = target
            self.vuln = bool(vuln)
            self.started_at = _now_iso()
            self.finished_at = None
            self.error = ""
            self.hosts_found = 0
            self.assets_stored = 0
            self.vulns_stored = 0
            self._thread = threading.Thread(
                target=self._run, args=(target, bool(vuln)), daemon=True)
            self._thread.start()
        return self.status(), 200

    def _run(self, target: str, vuln: bool):
        error = ""
        hosts = assets_n = vulns_n = 0
        try:
            nmap = nmap_path()
            if vuln:
                cmd = [nmap, "-sV", "--script", "vuln", target, "-oX", "-"]
            else:
                cmd = [nmap, "-sn", target, "-oX", "-"]
            store.upsert_connector(
                "nmap-discovery", kind="discovery", last_run=_now_iso())
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=1800)
            if proc.returncode != 0 and not proc.stdout.strip():
                error = proc.stderr.strip() or f"nmap exited {proc.returncode}"
            else:
                assets, found_vulns = parse_nmap_xml(proc.stdout)
                hosts = len(assets)
                for a in assets:
                    a["ts"] = _now_iso()
                    store.insert_asset(a)
                    assets_n += 1
                for v in found_vulns:
                    v["ts"] = _now_iso()
                    store.insert_vuln(v)
                    vulns_n += 1
        except subprocess.TimeoutExpired:
            error = "nmap scan timed out"
        except ET.ParseError:
            error = "could not parse nmap XML output"
        except Exception as exc:  # pragma: no cover - defensive
            error = f"scan failed: {exc}"
        finally:
            with self._lock:
                self.running = False
                self.finished_at = _now_iso()
                self.error = error
                self.hosts_found = hosts
                self.assets_stored = assets_n
                self.vulns_stored = vulns_n
            try:
                store.upsert_connector(
                    "nmap-discovery", kind="discovery",
                    last_run=_now_iso(), last_error=error or "")
            except Exception:  # pragma: no cover - store best-effort
                pass


# Module-level singleton, mirroring syslog_collector.COLLECTOR.
SCANNER = DiscoveryScanner()

#!/usr/bin/env python3
"""
syslog_collector.py — a live syslog listener (UDP + TCP) that writes received
messages into the persistent SOC Command Center store (console/store.py).

This is a real-time INGEST surface, not a verdict engine. Every received line is
stored verbatim (`raw`) via store.insert_event, exactly as it arrived on the
wire. anomaly_detector.py is never imported here — the frozen rules keep sole
ownership of severity/correlation; this module only records what a source sent.

HONESTY MODEL (matches docs/soc_command_center.md):
  - `raw` is the exact message received. Nothing rewrites evidence.
  - `severity` is SOURCE-REPORTED: it comes from the syslog PRI (the numeric
    priority a sender chose), decoded to the standard syslog severity keyword.
    When a message carries no PRI, severity is "" — we do NOT keyword-guess a
    level from the text. (The reference prototype's severity_from_text is
    deliberately NOT ported: guessing a severity would fabricate a verdict.)
  - Status reflects the REAL listener state — a bind that failed reports
    running=False with the actual error, never a fake "running".

SECURITY: binding a listener is a network service surface. The default bind is
127.0.0.1 (loopback only). Binding 0.0.0.0 exposes the port to the whole
network and is allowed only as an explicit opt-in — the caller must ask for it,
and the UI warns before doing so.

Stdlib only: socket, threading, re. The store is the single durable home.
"""

import re
import socket
import threading
from datetime import datetime, timezone

import store

# The standard syslog severities, indexed by the low 3 bits of the PRI value
# (RFC 3164 / RFC 5424). We report the source's own label, uppercased — never a
# guess. Facility (PRI >> 3) is recorded for context but is not a severity.
_SYSLOG_SEVERITY = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}

# "<PRI>" at the very start of a syslog frame, e.g. "<34>Oct 11 22:14:15 ...".
_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>(?P<rest>.*)$", re.S)

# RFC 3164 envelope: "Mon DD HH:MM:SS host rest" (space-padded day, no year).
# Kept local (a copy of normalize.RFC3164_RE) so this module has no dependency
# on the analyzer's import chain — it only ever touches the store.
_RFC3164_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$"
)

# Allowed bind targets. Loopback is the safe default; 0.0.0.0 is the explicit,
# network-exposing opt-in. "localhost" is accepted as an alias for loopback.
_LOOPBACK = "127.0.0.1"
_ANY = "0.0.0.0"
MAX_MSG_BYTES = 65535


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def parse_syslog(msg, src_ip=""):
    """Turn one received syslog message into a store event dict.

    Severity is decoded from the PRI (source-reported) or left "" when absent —
    never inferred from the text. `raw` is the message exactly as received.
    """
    raw = msg.rstrip("\r\n")
    severity = ""
    body = raw

    m = _PRI_RE.match(raw)
    if m:
        pri = int(m.group("pri"))
        # A syslog PRI is at most 191 (facility 23, severity 7); ignore anything
        # larger as not-a-PRI rather than mis-decoding it.
        if pri <= 191:
            severity = _SYSLOG_SEVERITY.get(pri & 0x07, "")
            body = m.group("rest")

    host = ""
    message = body
    em = _RFC3164_RE.match(body)
    if em:
        host = em.group("host")
        message = em.group("rest")

    return {
        "ts": _now_iso(),
        "source": f"syslog:{src_ip}" if src_ip else "syslog",
        "source_type": "syslog",
        "host": host,
        "src_ip": src_ip,
        "severity": severity,      # source-reported (PRI) or "" — never guessed
        "message": message,
        "raw": raw,                # verbatim wire line
    }


class SyslogCollector:
    """A threaded UDP+TCP syslog listener with an explicit start/stop lifecycle.

    Lives for the process (a background daemon), so it keeps receiving across
    HTTP requests. `start()` binds SYNCHRONOUSLY so a bind failure (port in use,
    privileged port without root) surfaces as an honest error immediately rather
    than a thread that dies out of sight.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads = []
        self._udp_sock = None
        self._tcp_sock = None
        self.running = False
        self.bind = _LOOPBACK
        self.port = 1514
        self.error = ""
        self.received = 0          # messages received on the wire since start
        self.stored = 0            # events actually inserted (new, post-dedupe)
        self.started_at = None
        self.last_event_at = None

    # -- lifecycle ---------------------------------------------------------

    def start(self, port=1514, bind=_LOOPBACK):
        """Bind UDP+TCP on (bind, port) and begin receiving. Restarts cleanly if
        already running. Returns status(); on a bind error, running is False and
        `error` carries the real reason."""
        with self._lock:
            self._stop_locked()
            bind = self._normalize_bind(bind)
            try:
                port = int(port)
            except (TypeError, ValueError):
                self.error = "port must be an integer"
                return self.status()
            if not (1 <= port <= 65535):
                self.error = "port must be between 1 and 65535"
                return self.status()

            self._stop.clear()
            self.error = ""
            self.received = 0
            self.stored = 0
            udp = tcp = None
            try:
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                udp.bind((bind, port))
                udp.settimeout(0.5)

                tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tcp.bind((bind, port))
                tcp.listen(32)
                tcp.settimeout(0.5)
            except OSError as exc:
                if udp:
                    udp.close()
                if tcp:
                    tcp.close()
                # Honest failure — never claim a listener that didn't bind.
                self.error = self._explain_bind_error(exc, bind, port)
                self.running = False
                return self.status()

            self._udp_sock, self._tcp_sock = udp, tcp
            self.bind, self.port = bind, port
            self.running = True
            self.started_at = _now_iso()
            store.init_db()
            self._spawn(self._udp_loop)
            self._spawn(self._tcp_loop)
            # Remember the last chosen listener config so the UI can pre-fill it.
            store.set_setting("syslog_port", str(port))
            store.set_setting("syslog_bind", bind)
            return self.status()

    def stop(self):
        with self._lock:
            self._stop_locked()
            return self.status()

    def _stop_locked(self):
        """Signal the loops to exit and close the sockets. Caller holds _lock."""
        self._stop.set()
        for sock in (self._udp_sock, self._tcp_sock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._udp_sock = self._tcp_sock = None
        for t in self._threads:
            if t is not threading.current_thread():
                t.join(timeout=1.5)
        self._threads = []
        self.running = False

    def _spawn(self, fn):
        t = threading.Thread(target=fn, daemon=True)
        t.start()
        self._threads.append(t)

    # -- receive loops -----------------------------------------------------

    def _udp_loop(self):
        sock = self._udp_sock
        while not self._stop.is_set() and sock is not None:
            try:
                data, addr = sock.recvfrom(MAX_MSG_BYTES)
            except socket.timeout:
                continue
            except OSError:
                break
            self._save(data.decode("utf-8", "replace"), addr[0] if addr else "")

    def _tcp_loop(self):
        sock = self._tcp_sock
        while not self._stop.is_set() and sock is not None:
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._tcp_client, args=(conn, addr),
                             daemon=True).start()

    def _tcp_client(self, conn, addr):
        src_ip = addr[0] if addr else ""
        with conn:
            conn.settimeout(1.0)
            buf = ""
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(MAX_MSG_BYTES)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk.decode("utf-8", "replace")
                # One event per line; keep a trailing partial for the next recv.
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if line.strip():
                        self._save(line, src_ip)
            if buf.strip():
                self._save(buf, src_ip)

    def _save(self, msg, src_ip):
        """Record one received message as a store event. Counts the receive even
        if it dedupes, so the status is an honest 'messages seen on the wire'."""
        for line in msg.splitlines() or [msg]:
            if not line.strip():
                continue
            self.received += 1
            self.last_event_at = _now_iso()
            try:
                if store.insert_event(parse_syslog(line, src_ip)):
                    self.stored += 1
            except Exception:
                # A store hiccup must never kill the listener; keep receiving.
                pass

    # -- status / helpers --------------------------------------------------

    def status(self):
        """The REAL listener state. `exposed` is True only when bound to a
        non-loopback address (0.0.0.0) — a signal the UI turns into a warning."""
        return {
            "running": self.running,
            "bind": self.bind,
            "port": self.port,
            "protocols": ["udp", "tcp"],
            "exposed": self.running and self.bind not in (_LOOPBACK, "localhost"),
            "receivedCount": self.received,
            "storedCount": self.stored,
            "startedAt": self.started_at if self.running else None,
            "lastEventAt": self.last_event_at,
            "error": self.error,
        }

    @staticmethod
    def _normalize_bind(bind):
        b = (bind or _LOOPBACK).strip()
        if b in ("localhost", "127.0.0.1", ""):
            return _LOOPBACK
        if b in ("0.0.0.0", "*", "any", "all"):
            return _ANY
        # Anything else is refused up front by the server route; default safe.
        return _LOOPBACK

    @staticmethod
    def _explain_bind_error(exc, bind, port):
        base = f"could not bind {bind}:{port} — {exc}"
        if port < 1024:
            return base + " (ports below 1024 need root; use 1514 for unprivileged collection)"
        return base


# Process-wide singleton — one collector for the whole server.
COLLECTOR = SyslogCollector()

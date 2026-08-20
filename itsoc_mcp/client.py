"""client.py — a tiny stdlib HTTP client for the local itsoc backend.

Read-only by construction: the only writes it can express are the ones the
existing /api surface already offers (POST /api/analyze kicks off an analysis;
everything else this package calls is a GET). Transport errors and backend error
bodies are turned into a single honest exception (ItsocError) that the tool layer
renders as `{"ok": false, "error": ...}` — never a made-up success.

Stdlib only (urllib) so the core backend still runs with ZERO extra installs; the
MCP SDK is the only third-party dependency and it lives in the server layer.
"""

import json
import os
import urllib.error
import urllib.request
import uuid

DEFAULT_BASE_URL = "http://127.0.0.1:8765"
DEFAULT_TIMEOUT = 30          # seconds for a single request (analysis is polled, not awaited)


class ItsocError(Exception):
    """A transport failure or a backend error body, carried honestly to the tool
    layer. `status` is the HTTP status when the backend answered, else None (the
    backend was unreachable)."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def _base_url(base_url=None):
    return (base_url or os.environ.get("ITSOC_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")


class ApiClient:
    """Thin proxy to the running backend. One instance per server process."""

    def __init__(self, base_url=None, timeout=DEFAULT_TIMEOUT):
        self.base_url = _base_url(base_url)
        self.timeout = timeout

    # -- low-level ---------------------------------------------------------
    def _open(self, req):
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
                ctype = resp.headers.get("Content-Type", "")
                disposition = resp.headers.get("Content-Disposition", "")
                return resp.status, body, ctype, disposition
        except urllib.error.HTTPError as e:
            # The backend answered with a 4xx/5xx — surface ITS honest message.
            body = e.read()
            msg = _error_message(body) or f"backend returned HTTP {e.code}"
            raise ItsocError(msg, status=e.code)
        except urllib.error.URLError as e:
            raise ItsocError(
                f"backend not reachable at {self.base_url} "
                f"(is `python3 console/serve.py` running?): {e.reason}")
        except (TimeoutError, OSError) as e:
            raise ItsocError(f"backend request failed: {e}")

    # -- JSON --------------------------------------------------------------
    def get_json(self, path):
        req = urllib.request.Request(self.base_url + path, method="GET")
        _status, body, _ctype, _disp = self._open(req)
        return _parse_json(body)

    def post_json(self, path, obj):
        data = json.dumps(obj or {}).encode()
        req = urllib.request.Request(
            self.base_url + path, data=data, method="POST",
            headers={"Content-Type": "application/json"})
        _status, body, _ctype, _disp = self._open(req)
        return _parse_json(body)

    def post_multipart(self, path, field_name, filename, data, extra_fields=None):
        """POST a single file (plus optional simple text fields) as
        multipart/form-data — the shape the existing upload path expects."""
        body, content_type = _encode_multipart(field_name, filename, data, extra_fields or {})
        req = urllib.request.Request(
            self.base_url + path, data=body, method="POST",
            headers={"Content-Type": content_type})
        _status, resp_body, _ctype, _disp = self._open(req)
        return _parse_json(resp_body)

    # -- raw bytes (exports) ----------------------------------------------
    def get_raw(self, path):
        """Return (body_bytes, content_type, filename) for a download endpoint."""
        req = urllib.request.Request(self.base_url + path, method="GET")
        _status, body, ctype, disp = self._open(req)
        return body, ctype, _filename_from_disposition(disp)


# ---------------------------------------------------------------------------
# helpers (pure, stdlib)
# ---------------------------------------------------------------------------
def _parse_json(body):
    if not body:
        return {}
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        raise ItsocError("backend returned a non-JSON body")


def _error_message(body):
    """Pull the backend's honest {"error": "..."} message out of an error body."""
    try:
        obj = json.loads(body)
    except (ValueError, TypeError):
        text = (body or b"").decode("utf-8", "replace").strip()
        return text[:300] or None
    if isinstance(obj, dict) and obj.get("error"):
        return str(obj["error"])
    return None


def _filename_from_disposition(disposition):
    marker = "filename="
    if marker in (disposition or ""):
        return disposition.split(marker, 1)[1].strip().strip('"') or None
    return None


def _encode_multipart(field_name, filename, data, extra_fields):
    boundary = "----itsoc-mcp-" + uuid.uuid4().hex
    parts = []
    for key, value in extra_fields.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n'
            f"{value}\r\n".encode())
    safe_name = (filename or "log").replace('"', "")
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{field_name}"; '
        f'filename="{safe_name}"\r\nContent-Type: application/octet-stream\r\n\r\n'
        .encode())
    parts.append(data if isinstance(data, (bytes, bytearray)) else str(data).encode())
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"

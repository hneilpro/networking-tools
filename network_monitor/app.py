"""Local-only web server for the Network Stability Monitor.

Same security posture as the RDP troubleshooter: 127.0.0.1 only,
random per-run token, pinned Host header, validated input only.
"""
from __future__ import annotations

import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .monitor import MonitorService
from .prober import http_check, parse_url, run_speed_test
from .web_ui import PAGE

MAX_BODY = 16_384
_speed_lock = threading.Lock()


def make_handler(token: str, service: MonitorService):
    class Handler(BaseHTTPRequestHandler):
        server_version = "NetworkMonitor/1.0"

        def _allowed(self) -> bool:
            host = (self.headers.get("Host") or "").split(":")[0].lower()
            if host not in ("127.0.0.1", "localhost"):
                self._send(403, {"error": "Forbidden host."})
                return False
            if self.headers.get("X-Tool-Token") != token and not self._is_page_load():
                self._send(403, {"error": "Missing or invalid session token. Reload the page from the app."})
                return False
            return True

        def _is_page_load(self) -> bool:
            if self.path == "/" or self.path.startswith("/?"):
                query = parse_qs(urlparse(self.path).query)
                return secrets.compare_digest((query.get("token") or [""])[0], token)
            return False

        def _send(self, code: int, payload, content_type="application/json"):
            if isinstance(payload, (dict, list)):
                body = json.dumps(payload).encode()
            else:
                body = str(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/":
                if not self._allowed():
                    return
                self._send(200, PAGE, "text/html; charset=utf-8")
            elif path == "/api/status":
                if not self._allowed():
                    return
                self._send(200, service.status())
            elif path == "/api/export.csv":
                if not self._allowed():
                    return
                self._send(200, service.export_csv(), "text/csv; charset=utf-8")
            else:
                self._send(404, {"error": "Not found."})

        def do_POST(self):
            path = urlparse(self.path).path
            if path not in ("/api/target", "/api/http-check", "/api/speedtest"):
                self._send(404, {"error": "Not found."})
                return
            if not self._allowed():
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length > MAX_BODY:
                self._send(413, {"error": "Request too large."})
                return
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send(400, {"error": "Request was not valid JSON."})
                return
            if not isinstance(data, dict):
                self._send(400, {"error": "Request must be a JSON object."})
                return
            if path == "/api/target":
                try:
                    parsed = parse_url(data.get("url", ""))
                except ValueError as exc:
                    self._send(400, {"error": str(exc)})
                    return
                self._send(200, {"target": service.add_custom_target(parsed)})
            elif path == "/api/http-check":
                try:
                    parsed = parse_url(data.get("url", ""))
                except ValueError as exc:
                    self._send(400, {"error": str(exc)})
                    return
                self._send(200, {"result": http_check(parsed)})
            else:  # /api/speedtest
                if not _speed_lock.acquire(blocking=False):
                    self._send(409, {"error": "A speed test is already running. Wait for it to finish."})
                    return
                try:
                    result = run_speed_test()
                finally:
                    _speed_lock.release()
                self._send(200, {"result": result})

    return Handler


def build_server(service: MonitorService | None = None):
    """Create (server, token, url) without starting it. The hub uses
    this to run the monitor alongside the other tools in one process."""
    token = secrets.token_urlsafe(24)
    if service is None:
        service = MonitorService()
    service.start()
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(token, service))
    url = f"http://127.0.0.1:{server.server_address[1]}/?token={token}"
    return server, token, url


def serve(open_browser: bool = True) -> None:
    server, _token, url = build_server()
    print(f"Network Stability Monitor running at {url}", flush=True)
    print("Press Ctrl+C to stop. (Local only: nothing is reachable from your network.)", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()

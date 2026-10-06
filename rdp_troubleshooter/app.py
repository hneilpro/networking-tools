"""Local-only web server for the RDP troubleshooter.

Security posture:
- Binds 127.0.0.1 only; never exposed to the network.
- Every request must carry a random per-run token (blocks other local
  websites from poking this server via your browser).
- Host header is pinned to localhost, and all input is validated.
- Nothing is logged except startup errors; no credentials are ever asked for.
"""
from __future__ import annotations

import json
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .diagnostics import RDP_PORT, run_diagnosis
from .network_utils import (local_ipv4, parse_port, parse_target,
                            validate_scan_cidr)
from .scanner import detect_network, scan_network
from .web_ui import PAGE

MAX_BODY = 16_384
_scan_lock = threading.Lock()


def make_handler(token: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "RdpTroubleshooter/1.0"

        # --- helpers -----------------------------------------------------
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
            # The initial page load carries the token in the URL instead.
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

        def log_message(self, fmt, *args):  # keep the console clean
            pass

        # --- routes ------------------------------------------------------
        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/":
                if not self._allowed():
                    return
                self._send(200, PAGE, "text/html; charset=utf-8")
            elif path == "/api/local-info":
                if not self._allowed():
                    return
                self._send(200, detect_network())
            else:
                self._send(404, {"error": "Not found."})

        def do_POST(self):
            path = urlparse(self.path).path
            if path not in ("/api/scan", "/api/diagnose"):
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
            if path == "/api/scan":
                self._handle_scan(data)
            else:
                self._handle_diagnose(data)

        def _handle_scan(self, data: dict):
            raw = data.get("cidr")
            if raw:
                try:
                    network = validate_scan_cidr(raw)
                except ValueError as exc:
                    self._send(400, {"error": str(exc)})
                    return
            else:
                info = detect_network()
                if not info["subnet"]:
                    self._send(400, {"error": "Could not detect your local network. Connect to Wi-Fi/Ethernet and try again."})
                    return
                try:
                    network = validate_scan_cidr(info["subnet"])
                except ValueError as exc:
                    self._send(400, {"error": str(exc)})
                    return
            if not _scan_lock.acquire(blocking=False):
                self._send(409, {"error": "A scan is already running. Wait for it to finish."})
                return
            try:
                devices = scan_network(network)
            finally:
                _scan_lock.release()
            self._send(200, {"network": str(network), "devices": devices})

        def _handle_diagnose(self, data: dict):
            try:
                target = parse_target(data.get("target", ""))
                port = parse_port(data.get("port", RDP_PORT), RDP_PORT)
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            scenario = data.get("scenario", "lan")
            if scenario not in ("lan", "vpn", "internet"):
                scenario = "lan"
            symptom = data.get("symptom", "generic")
            if symptom not in ("generic", "not_found", "timeout", "refused",
                               "login_rejected", "black_screen"):
                symptom = "generic"
            result = run_diagnosis(target, port=port, scenario=scenario,
                                   symptom=symptom, local_ip=local_ipv4())
            self._send(200, {"result": result.to_dict()})

    return Handler


def serve(open_browser: bool = True) -> None:
    token = secrets.token_urlsafe(24)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(token))
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/?token={token}"
    print(f"RDP Troubleshooter running at {url}", flush=True)
    print("Press Ctrl+C to stop. (Local only: nothing is reachable from your network.)", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()

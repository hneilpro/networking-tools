"""Hub server: homepage menu + lazy in-process launch of each tool.

Why one process instead of spawning each tool as a subprocess: no
orphaned servers, no port bookkeeping, and the tools' own servers are
reused exactly as they run standalone. Each tool still gets its own
random token and its own 127.0.0.1 port; the hub only redirects to it.

Same posture as the tools: 127.0.0.1 only, hub token on the homepage,
pinned Host header.
"""
from __future__ import annotations

import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from network_monitor.app import build_server as build_monitor_server
from rdp_troubleshooter.app import build_server as build_rdp_server

from .web_ui import PAGE

_BUILDERS = {
    "rdp": ("Remote Desktop Troubleshooter", build_rdp_server),
    "monitor": ("Network Stability Monitor", build_monitor_server),
}


class ToolLauncher:
    """Starts each tool server at most once, on first pick."""

    def __init__(self, builders=None):
        self._builders = builders or _BUILDERS
        self._lock = threading.Lock()
        self._started: dict[str, tuple[str, str]] = {}  # key -> (name, url)

    def launch(self, key: str) -> str | None:
        """Return the tool's URL, starting its server if needed."""
        if key not in self._builders:
            return None
        with self._lock:
            if key in self._started:
                return self._started[key][1]
            name, builder = self._builders[key]
            server, _token, url = builder()
            thread = threading.Thread(target=server.serve_forever, daemon=True,
                                      name=f"hub-{key}")
            thread.start()
            self._started[key] = (name, url)
            return url

    def started(self) -> dict:
        with self._lock:
            return dict(self._started)


def make_handler(token: str, launcher: ToolLauncher):
    class Handler(BaseHTTPRequestHandler):
        server_version = "NetworkingToolsHub/1.0"

        def _allowed(self) -> bool:
            host = (self.headers.get("Host") or "").split(":")[0].lower()
            if host not in ("127.0.0.1", "localhost"):
                self._send(403, b"Forbidden host.", "text/plain; charset=utf-8")
                return False
            query = parse_qs(urlparse(self.path).query)
            if not secrets.compare_digest((query.get("token") or [""])[0], token):
                self._send(403, b"Missing or invalid session token. Reload the page from the app.",
                           "text/plain; charset=utf-8")
                return False
            return True

        def _send(self, code: int, body: bytes, content_type: str, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; connect-src 'self'")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/":
                if not self._allowed():
                    return
                self._send(200, PAGE.replace("__TOKEN__", token).encode(), "text/html; charset=utf-8")
            elif path.startswith("/launch/"):
                if not self._allowed():
                    return
                key = path[len("/launch/"):]
                url = launcher.launch(key)
                if url is None:
                    self._send(404, b"Unknown tool.", "text/plain; charset=utf-8")
                    return
                self._send(302, b"", "text/plain; charset=utf-8", {"Location": url})
            else:
                self._send(404, b"Not found.", "text/plain; charset=utf-8")

    return Handler


def build_server(launcher: ToolLauncher | None = None):
    token = secrets.token_urlsafe(24)
    launcher = launcher or ToolLauncher()
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(token, launcher))
    url = f"http://127.0.0.1:{server.server_address[1]}/?token={token}"
    return server, token, url


def serve(open_browser: bool = True) -> None:
    server, _token, url = build_server()
    print(f"Networking Tools running at {url}", flush=True)
    print("Pick a tool on the homepage; it starts when you pick it.", flush=True)
    print("Press Ctrl+C to stop everything. (Local only: nothing is reachable from your network.)", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()

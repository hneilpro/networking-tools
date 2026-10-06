"""Probes: ping (system binary, validated host, no shell), TCP fallback,
one-shot HTTP connection breakdown, and an on-demand speed test.

Stdlib only. Every host that reaches a subprocess argument list or a
socket has passed validation in this module or network_utils first.
"""
from __future__ import annotations

import platform
import re
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from rdp_troubleshooter.network_utils import parse_target

_PING_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)
MAX_URL_LEN = 2048
SPEED_DOWNLOAD_BYTES = 5_000_000
SPEED_UPLOAD_BYTES = 1_000_000
SPEED_MAX_BYTES = 25_000_000
USER_AGENT = "networking-tools-monitor/1.0"


@dataclass
class ProbeResult:
    ok: bool
    ms: float | None
    method: str  # "ping" | "tcp" | "none"
    detail: str = ""


@dataclass
class ParsedUrl:
    url: str
    scheme: str
    host: str
    port: int
    path: str

    @property
    def default_tcp_port(self) -> int:
        return self.port


def parse_url(raw: str) -> ParsedUrl:
    """Validate a user-supplied URL for monitoring/HTTP checks.

    Only http/https, no embedded credentials, no whitespace. A bare host
    (no scheme) is treated as https."""
    if raw is None:
        raise ValueError("Enter a URL or host to test.")
    url = str(raw).strip()
    if not url:
        raise ValueError("Enter a URL or host to test.")
    if len(url) > MAX_URL_LEN:
        raise ValueError("That URL is too long.")
    if any(ch.isspace() for ch in url):
        raise ValueError("URLs can't contain spaces.")
    if "://" not in url:
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")
    if parts.username or parts.password:
        raise ValueError("Don't put a username or password in the URL.")
    host = parts.hostname
    if not host:
        raise ValueError("That URL has no host in it.")
    if ":" in host:
        raise ValueError("IPv6 targets aren't supported by these tools yet. Use the IPv4 address or hostname.")
    host = parse_target(host)  # validates IP/hostname, lowercases hosts
    try:
        port = parts.port
    except ValueError:
        raise ValueError("That URL has an invalid port.")
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    is_default_port = (parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80)
    normalized = f"{parts.scheme}://{host}{path}" if is_default_port else f"{parts.scheme}://{host}:{port}{path}"
    return ParsedUrl(url=normalized, scheme=parts.scheme, host=host, port=port, path=path)


def parse_ping_ms(output: str) -> float | None:
    match = _PING_TIME_RE.search(output or "")
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def ping_latency(host: str, timeout_s: float = 1.0) -> ProbeResult:
    """One ping via the OS binary. Args are a fixed list, never a shell,
    and `host` must already be validated."""
    system = platform.system().lower()
    timeout_ms = max(200, int(timeout_s * 1000))
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 3)
    except OSError:
        return ProbeResult(False, None, "none", "Ping isn't available on this PC.")
    except subprocess.TimeoutExpired:
        return ProbeResult(False, None, "ping", "Ping timed out.")
    ms = parse_ping_ms(proc.stdout)
    if ms is not None:
        return ProbeResult(True, ms, "ping")
    return ProbeResult(False, None, "ping", "No ping reply (the target may block ping).")


def tcp_latency(host: str, port: int, timeout_s: float = 1.5) -> ProbeResult:
    """TCP connect timing. Resolves hostnames; used as the fallback when
    ping is blocked, and never counted as proof of 'down' by itself."""
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return ProbeResult(False, None, "tcp", f"Could not resolve '{host}'.")
    if not infos:
        return ProbeResult(False, None, "tcp", f"Could not resolve '{host}'.")
    ip = infos[0][4][0]
    start = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        sock.connect((ip, port))
        return ProbeResult(True, (time.monotonic() - start) * 1000, "tcp")
    except OSError as exc:
        return ProbeResult(False, None, "tcp", f"TCP connect failed: {exc.strerror or exc}.")
    finally:
        sock.close()


def probe_target(host: str, tcp_port: int, timeout_s: float = 1.0) -> ProbeResult:
    """Ping first; if ping fails, a successful TCP connect still proves
    reachability and gives a (handshake) latency. Only both failing
    counts as a lost sample."""
    result = ping_latency(host, timeout_s)
    if result.ok:
        return result
    fallback = tcp_latency(host, tcp_port, timeout_s=1.5)
    if fallback.ok:
        fallback.detail = "Ping blocked; measured by TCP connect instead."
        return fallback
    return ProbeResult(False, None, "none", fallback.detail or result.detail)


def http_check(parsed: ParsedUrl, timeout_s: float = 10.0) -> dict:
    """One-shot connection breakdown: DNS, TCP, TLS, first byte, total."""
    out: dict = {"url": parsed.url, "host": parsed.host, "port": parsed.port,
                 "scheme": parsed.scheme, "ok": False}
    start = time.monotonic()
    try:
        infos = socket.getaddrinfo(parsed.host, parsed.port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        out["error"] = f"DNS lookup failed: {exc}."
        out["total_ms"] = _ms(start)
        return out
    out["dns_ms"] = _ms(start)
    out["resolved_ip"] = infos[0][4][0]

    tcp_start = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        sock.connect((parsed.host, parsed.port))
    except OSError as exc:
        out["error"] = f"TCP connect failed: {exc.strerror or exc}."
        out["total_ms"] = _ms(start)
        sock.close()
        return out
    out["tcp_ms"] = _ms(tcp_start)

    if parsed.scheme == "https":
        tls_start = time.monotonic()
        try:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=parsed.host)
        except (ssl.SSLError, OSError) as exc:
            out["error"] = f"TLS handshake failed: {exc}."
            out["total_ms"] = _ms(start)
            sock.close()
            return out
        out["tls_ms"] = _ms(tls_start)

    request = (f"GET {parsed.path} HTTP/1.1\r\nHost: {parsed.host}\r\n"
               f"User-Agent: {USER_AGENT}\r\nConnection: close\r\n\r\n").encode()
    first_byte_at = None
    status = None
    total_bytes = 0
    try:
        read_start = time.monotonic()
        sock.sendall(request)
        while total_bytes < 65_536:
            chunk = sock.recv(8192)
            if not chunk:
                break
            if first_byte_at is None:
                first_byte_at = time.monotonic()
                first_line = chunk.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                parts = first_line.split(" ", 2)
                if len(parts) >= 2 and parts[1].isdigit():
                    status = int(parts[1])
            total_bytes += len(chunk)
        out["ttfb_ms"] = round((first_byte_at - read_start) * 1000, 2) if first_byte_at else None
    except OSError as exc:
        out["error"] = f"Request failed: {exc.strerror or exc}."
        out["total_ms"] = _ms(start)
        return out
    finally:
        sock.close()
    out["status"] = status
    out["bytes_read"] = total_bytes
    out["total_ms"] = _ms(start)
    out["ok"] = status is not None
    if status is None:
        out["error"] = "The server replied, but not with a readable HTTP status."
    return out


def _ms(since: float) -> float:
    return round((time.monotonic() - since) * 1000, 2)


def run_speed_test(download_bytes: int = SPEED_DOWNLOAD_BYTES,
                   upload_bytes: int = SPEED_UPLOAD_BYTES) -> dict:
    """On-demand throughput via Cloudflare's public speed endpoints.
    Single-threaded stdlib HTTP: a rough check, not a gigabit benchmark.
    Sits outside the monitor loop on purpose — it saturates the link."""
    download_bytes = min(max(100_000, download_bytes), SPEED_MAX_BYTES)
    upload_bytes = min(max(10_000, upload_bytes), SPEED_MAX_BYTES)
    out: dict = {"ok": False, "note": "Single-connection test. Fast lines may read low; "
                                      "latency graphs will spike while this runs."}
    url = f"https://speed.cloudflare.com/__down?bytes={download_bytes}"
    start = time.monotonic()
    got = 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as resp:
            while True:
                chunk = resp.read(65_536)
                if not chunk:
                    break
                got += len(chunk)
    except (urllib.error.URLError, OSError) as exc:
        out["error"] = f"Download test failed: {exc}."
        return out
    seconds = time.monotonic() - start
    if seconds <= 0 or got == 0:
        out["error"] = "Download test got no data."
        return out
    out["download_mbps"] = round(got * 8 / seconds / 1_000_000, 2)
    out["download_bytes"] = got

    payload = b"0" * upload_bytes
    start = time.monotonic()
    try:
        req = urllib.request.Request("https://speed.cloudflare.com/__up", data=payload,
                                     headers={"User-Agent": USER_AGENT,
                                              "Content-Type": "application/octet-stream"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
    except (urllib.error.URLError, OSError) as exc:
        out["error"] = f"Upload test failed: {exc}. Download result above still counts."
        out["ok"] = True
        return out
    seconds = time.monotonic() - start
    if seconds > 0:
        out["upload_mbps"] = round(upload_bytes * 8 / seconds / 1_000_000, 2)
        out["upload_bytes"] = upload_bytes
    out["ok"] = True
    return out

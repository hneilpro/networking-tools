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
import statistics
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from rdp_troubleshooter.network_utils import parse_target

_PING_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)
MAX_URL_LEN = 2048
SPEED_DOWNLOAD_SECONDS = 10.0
SPEED_UPLOAD_SECONDS = 8.0
SPEED_DOWNLOAD_CHUNK_BYTES = 10_000_000
SPEED_UPLOAD_CHUNK_BYTES = 262_144  # small chunks: a timed phase can only
# overshoot its deadline by one in-flight chunk per stream
SPEED_MAX_TOTAL_BYTES = 600_000_000  # safety cap across one whole test
SPEED_PARALLEL_STREAMS = 4
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


# Routers commonly listen on one of these even when they ignore ping and
# keep their web UI off port 80 (or sit behind a virtual NAT, as in WSL).
GATEWAY_TCP_PORTS = (80, 443, 53, 8080, 22)


def probe_gateway(host: str, timeout_s: float = 1.0) -> ProbeResult:
    """Probe a gateway/router: ping, then TCP on several common ports.

    Consumer routers often drop ICMP and expose no web UI on the LAN
    side, so a single-port fallback (the old behaviour) called healthy
    gateways 'down'. One answered port is enough to prove reachability;
    all of them failing still only proves the *probes* were refused —
    the monitor cross-checks internet targets before calling an outage."""
    result = ping_latency(host, timeout_s)
    if result.ok:
        return result
    for port in GATEWAY_TCP_PORTS:
        fallback = tcp_latency(host, port, timeout_s=0.75)
        if fallback.ok:
            fallback.detail = f"Ping blocked; measured by TCP connect on port {port} instead."
            return fallback
    return ProbeResult(False, None, "none",
                       "Gateway answered neither ping nor TCP on ports "
                       "80/443/53/8080/22. Its probes may be blocked.")


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


def bufferbloat_grade(delta_ms: float | None) -> str | None:
    """Grade the latency increase under load. Bands follow the common
    bufferbloat grading used by public tests: a few ms is invisible,
    hundreds means calls and games fall apart while the line is busy."""
    if delta_ms is None:
        return None
    if delta_ms <= 5:
        return "A+"
    if delta_ms <= 15:
        return "A"
    if delta_ms <= 30:
        return "B"
    if delta_ms <= 60:
        return "C"
    if delta_ms <= 120:
        return "D"
    return "F"


def _median_or_none(values: list[float]) -> float | None:
    return round(statistics.median(values), 2) if values else None


def _timed_phase(duration_s: float, do_once, parallel: int) -> tuple[int, float, str | None]:
    """Run do_once(deadline) in `parallel` workers until the deadline.
    Returns (total_bytes, elapsed_s, first_error). A single shared byte
    cap keeps a fast line from turning the test into a data binge."""
    start = time.monotonic()
    deadline = start + duration_s
    state = {"total": 0}
    lock = threading.Lock()
    errors: list[str] = []

    def worker() -> None:
        while time.monotonic() < deadline:
            with lock:
                if state["total"] >= SPEED_MAX_TOTAL_BYTES:
                    return
            try:
                n = do_once(deadline)
            except (urllib.error.URLError, OSError) as exc:
                with lock:
                    if not errors:
                        errors.append(str(exc))
                return
            if not n:
                return
            with lock:
                state["total"] += n

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(max(1, parallel))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=duration_s + 20)
    return state["total"], time.monotonic() - start, (errors[0] if errors else None)


def run_speed_test(download_s: float = SPEED_DOWNLOAD_SECONDS,
                   upload_s: float = SPEED_UPLOAD_SECONDS,
                   parallel: int = SPEED_PARALLEL_STREAMS,
                   probe_fn=None, urlopen_fn=None) -> dict:
    """Sustained, time-boxed throughput via Cloudflare's public speed
    endpoints. Timed phases (default ~10s down, ~8s up) instead of one
    small fixed-size burst, so the connection gets past its slow start
    and the number reflects the line, not the ramp. While the download
    saturates the link, latency probes keep running so the result also
    carries a bufferbloat (latency-under-load) grade. Sits outside the
    monitor loop on purpose. probe_fn/urlopen_fn are injectable for tests."""
    probe_fn = probe_fn or probe_target
    urlopen_fn = urlopen_fn or urllib.request.urlopen
    download_s = max(0.05, min(float(download_s), 60.0))
    upload_s = max(0.05, min(float(upload_s), 60.0))
    out: dict = {"ok": False,
                 "note": "Sustained multi-stream test. Still an estimate on very fast "
                         "lines; latency graphs will spike while this runs, which is "
                         "the test, not an outage."}

    idle_values: list[float] = []
    for _ in range(3):
        result = probe_fn("1.1.1.1", 443)
        if result.ok and result.ms is not None:
            idle_values.append(result.ms)
    out["idle_latency_ms"] = _median_or_none(idle_values)

    loaded_values: list[float] = []
    loaded_stop = threading.Event()

    def loaded_prober() -> None:
        while not loaded_stop.is_set():
            result = probe_fn("1.1.1.1", 443)
            if result.ok and result.ms is not None:
                loaded_values.append(result.ms)
            loaded_stop.wait(0.1)

    def download_once(deadline: float) -> int:
        url = f"https://speed.cloudflare.com/__down?bytes={SPEED_DOWNLOAD_CHUNK_BYTES}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        n = 0
        timeout = max(2.0, min(20.0, deadline - time.monotonic() + 1.0))
        with urlopen_fn(req, timeout=timeout) as resp:
            while time.monotonic() < deadline:
                chunk = resp.read(65_536)
                if not chunk:
                    break
                n += len(chunk)
        return n

    prober_thread = threading.Thread(target=loaded_prober, daemon=True)
    prober_thread.start()
    try:
        got, down_seconds, down_error = _timed_phase(download_s, download_once, parallel)
    finally:
        loaded_stop.set()
        prober_thread.join(timeout=5)
    out["download_seconds"] = round(down_seconds, 2)
    out["loaded_latency_ms"] = _median_or_none(loaded_values)
    if out["idle_latency_ms"] is not None and out["loaded_latency_ms"] is not None:
        out["bufferbloat_ms"] = round(out["loaded_latency_ms"] - out["idle_latency_ms"], 2)
    else:
        out["bufferbloat_ms"] = None
    out["bufferbloat_grade"] = bufferbloat_grade(out["bufferbloat_ms"])
    if got == 0 or down_seconds <= 0:
        out["error"] = f"Download test failed: {down_error}." if down_error \
            else "Download test got no data."
        return out
    out["download_mbps"] = round(got * 8 / down_seconds / 1_000_000, 2)
    out["download_bytes"] = got

    payload = b"0" * SPEED_UPLOAD_CHUNK_BYTES

    def upload_once(deadline: float) -> int:
        if time.monotonic() >= deadline:
            return 0
        req = urllib.request.Request("https://speed.cloudflare.com/__up", data=payload,
                                     headers={"User-Agent": USER_AGENT,
                                              "Content-Type": "application/octet-stream"})
        timeout = max(2.0, min(20.0, deadline - time.monotonic() + 1.0))
        with urlopen_fn(req, timeout=timeout) as resp:
            resp.read()
        return len(payload)

    sent, up_seconds, up_error = _timed_phase(upload_s, upload_once, parallel)
    out["upload_seconds"] = round(up_seconds, 2)
    if sent == 0 or up_seconds <= 0:
        out["error"] = f"Upload test failed: {up_error}. Download result above still counts." \
            if up_error else "Upload test sent no data. Download result above still counts."
        out["ok"] = True
        out["data_used_bytes"] = got
        return out
    out["upload_mbps"] = round(sent * 8 / up_seconds / 1_000_000, 2)
    out["upload_bytes"] = sent
    out["data_used_bytes"] = got + sent
    out["ok"] = True
    return out

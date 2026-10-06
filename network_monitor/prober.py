"""Probes: ping (system binary, validated host, no shell), TCP fallback,
one-shot HTTP connection breakdown, and an on-demand speed test.

Stdlib only. Every host that reaches a subprocess argument list or a
socket has passed validation in this module or network_utils first.
"""
from __future__ import annotations

import http.client
import math
import os
import platform
import re
import socket
import ssl
import statistics
import subprocess
import threading
import time
import urllib.parse
from dataclasses import dataclass

from rdp_troubleshooter.network_utils import parse_target

_PING_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)
MAX_URL_LEN = 2048
SPEED_DOWNLOAD_SECONDS = 25.0
SPEED_UPLOAD_SECONDS = 20.0
# The first moments of any transfer are TCP slow-start ramping, not the
# line's real speed; that warmup is discarded from the headline number.
SPEED_WARMUP_SECONDS = 2.0
SPEED_HOST = "speed.cloudflare.com"
# One persistent connection per worker is reused for back-to-back
# large transfers. Crediting bytes only when a whole request finished,
# and paying a fresh TLS handshake per small request (the old design),
# capped the old test far below the line it was measuring.
SPEED_DOWNLOAD_REQUEST_BYTES = 25_000_000
SPEED_DOWNLOAD_REQUEST_LADDER = (25_000_000, 10_000_000, 5_000_000, 1_000_000)
SPEED_UPLOAD_REQUEST_BYTES = 5_000_000
SPEED_UPLOAD_REQUEST_LADDER = (5_000_000, 1_000_000, 262_144)
SPEED_READ_CHUNK_BYTES = 262_144
SPEED_BUCKET_SECONDS = 0.25
SPEED_MAX_CONSECUTIVE_FAILURES = 4
SPEED_MIN_COMPLETE_RATIO = 0.8
SPEED_MAX_TOTAL_BYTES = 2_000_000_000  # safety cap per phase
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


@dataclass
class _TransferResult:
    status: int | None
    bytes_moved: int
    completed: bool  # the request finished cleanly end-to-end


class _SpeedTransportError(Exception):
    """One transfer failed; the phase runner decides retry vs. give up."""


class _CloudflareConnection:
    """One worker's persistent connection to the speed endpoints.

    http.client with an explicit Connection: keep-alive header, so a
    worker pays the DNS/TCP/TLS cost once and then streams back-to-back
    transfers. Bytes are reported through on_chunk as they are read or
    written, never held until a request completes."""

    def __init__(self, host: str = SPEED_HOST, port: int = 443,
                 use_tls: bool = True, timeout: float = 15.0):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self._conn = None
        self._upload_block: bytes | None = None
        self.connections_made = 0
        self.colo: str | None = None

    def _ensure(self):
        if self._conn is None:
            cls = http.client.HTTPSConnection if self.use_tls else http.client.HTTPConnection
            self._conn = cls(self.host, self.port, timeout=self.timeout)
        return self._conn

    def _prepare(self, conn, deadline: float) -> None:
        # Count an actual connection each time the socket is (re)opened,
        # including server-initiated closes that http.client reopens
        # silently, and bound every blocking call by the phase deadline
        # so a stalled transfer cannot stretch the phase by seconds.
        if conn.sock is None:
            self.connections_made += 1
        self._set_deadline_timeout(conn, deadline)

    def _set_deadline_timeout(self, conn, deadline: float) -> None:
        if conn.sock is not None:
            remaining = deadline - time.monotonic()
            conn.sock.settimeout(max(0.5, min(self.timeout, remaining + 1.0)))

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None

    def _note_headers(self, resp) -> None:
        ray = resp.getheader("CF-RAY") or resp.getheader("cf-ray")
        if ray and "-" in ray:
            self.colo = ray.rsplit("-", 1)[-1].strip() or self.colo

    def download(self, request_bytes: int, deadline: float, should_run,
                 on_chunk) -> _TransferResult:
        conn = self._ensure()
        self._prepare(conn, deadline)
        try:
            conn.request("GET", f"/__down?bytes={int(request_bytes)}",
                         headers={"User-Agent": USER_AGENT,
                                  "Accept-Encoding": "identity",
                                  "Connection": "keep-alive"})
            self._set_deadline_timeout(conn, deadline)
            resp = conn.getresponse()
            self._note_headers(resp)
            if resp.status != 200:
                try:
                    resp.read(65_536)
                except (http.client.HTTPException, OSError):
                    pass
                self.close()
                return _TransferResult(resp.status, 0, False)
            moved = 0
            completed = True
            while moved < request_bytes:
                if not should_run():
                    completed = False
                    break
                chunk = resp.read(min(SPEED_READ_CHUNK_BYTES, request_bytes - moved))
                if not chunk:
                    completed = moved >= request_bytes
                    break
                moved += len(chunk)
                on_chunk(len(chunk))
            if not completed:
                # A partially-read response cannot be reused safely.
                self.close()
            return _TransferResult(resp.status, moved, completed)
        except (http.client.HTTPException, OSError) as exc:
            self.close()
            raise _SpeedTransportError(str(exc) or exc.__class__.__name__) from exc

    def upload(self, request_bytes: int, deadline: float, should_run,
               on_chunk) -> _TransferResult:
        conn = self._ensure()
        self._prepare(conn, deadline)
        if self._upload_block is None:
            # Incompressible payload: repeated random block. Nothing in
            # this stack gzips the body, but random data keeps the test
            # honest even if something downstream ever tries.
            self._upload_block = os.urandom(1_048_576)
        block = self._upload_block
        try:
            conn.putrequest("POST", "/__up", skip_accept_encoding=True)
            conn.putheader("User-Agent", USER_AGENT)
            conn.putheader("Content-Type", "application/octet-stream")
            conn.putheader("Content-Length", str(int(request_bytes)))
            conn.putheader("Connection", "keep-alive")
            conn.endheaders()
            self._set_deadline_timeout(conn, deadline)
            moved = 0
            completed = True
            while moved < request_bytes:
                if not should_run():
                    completed = False
                    break
                segment = block if request_bytes - moved >= len(block) \
                    else block[:request_bytes - moved]
                conn.send(segment)
                moved += len(segment)
                on_chunk(len(segment))
            if not completed:
                self.close()
                return _TransferResult(None, moved, False)
            self._set_deadline_timeout(conn, deadline)
            resp = conn.getresponse()
            self._note_headers(resp)
            while True:
                chunk = resp.read(65_536)
                if not chunk:
                    break
            if resp.status != 200:
                self.close()
            return _TransferResult(resp.status, moved, resp.status == 200)
        except (http.client.HTTPException, OSError) as exc:
            self.close()
            raise _SpeedTransportError(str(exc) or exc.__class__.__name__) from exc


def _nearest_rank(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100.0 * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


_RETRYABLE_STATUSES = frozenset({403, 408, 413, 429, 500, 502, 503, 504})


def _run_phase(duration_s: float, parallel: int, transport_factory,
               direction: str, warmup_s: float) -> dict:
    """Run one timed transfer phase over persistent per-worker streams.

    Bytes land in quarter-second buckets as they move. The headline is
    the post-warmup bucket total over the post-warmup time; the p90
    bucket rate rides along as a cross-check. A worker that fails
    repeatedly retries with a smaller request (servers refuse large
    transfers before small ones) and only gives up after several
    consecutive failures; every failure is recorded, and a phase whose
    workers died early is flagged unreliable instead of graded."""
    duration_s = max(0.05, float(duration_s))
    warmup_s = max(0.0, min(float(warmup_s), duration_s * 0.4))
    ladder = SPEED_DOWNLOAD_REQUEST_LADDER if direction == "download" \
        else SPEED_UPLOAD_REQUEST_LADDER
    start = time.monotonic()
    deadline = start + duration_s
    lock = threading.Lock()
    buckets: dict[int, int] = {}
    state = {"total": 0, "requests": 0, "completed_requests": 0,
             "connections": 0, "workers_failed": 0, "colo": None}
    errors: list[str] = []

    def should_run() -> bool:
        if time.monotonic() >= deadline:
            return False
        with lock:
            return state["total"] < SPEED_MAX_TOTAL_BYTES

    def on_chunk(n: int) -> None:
        now = time.monotonic()
        idx = int((now - start) / SPEED_BUCKET_SECONDS)
        with lock:
            state["total"] += n
            buckets[idx] = buckets.get(idx, 0) + n

    def note_error(message: str) -> None:
        with lock:
            if len(errors) < 8:
                errors.append(message)

    def worker() -> None:
        conn = transport_factory()
        ladder_idx = 0
        consecutive_failures = 0
        failed = False
        try:
            while should_run():
                request_bytes = ladder[ladder_idx]
                with lock:
                    state["requests"] += 1
                try:
                    if direction == "download":
                        result = conn.download(request_bytes, deadline,
                                               should_run, on_chunk)
                    else:
                        result = conn.upload(request_bytes, deadline,
                                             should_run, on_chunk)
                except _SpeedTransportError as exc:
                    note_error(f"{direction}: {exc}")
                    consecutive_failures += 1
                    if consecutive_failures >= SPEED_MAX_CONSECUTIVE_FAILURES:
                        failed = True
                        break
                    _sleep_brief(deadline, consecutive_failures)
                    continue
                except Exception as exc:  # a broken transport must not hang the phase
                    note_error(f"{direction}: unexpected {exc.__class__.__name__}: {exc}")
                    consecutive_failures += 1
                    if consecutive_failures >= SPEED_MAX_CONSECUTIVE_FAILURES:
                        failed = True
                        break
                    _sleep_brief(deadline, consecutive_failures)
                    continue
                if getattr(conn, "colo", None):
                    with lock:
                        state["colo"] = conn.colo
                if not should_run():
                    break  # deadline/cap landed mid-request; not a failure
                if result.status == 200 and result.bytes_moved > 0:
                    consecutive_failures = 0
                    if result.completed:
                        with lock:
                            state["completed_requests"] += 1
                    continue
                if result.status in _RETRYABLE_STATUSES:
                    note_error(f"{direction}: HTTP {result.status} "
                               f"at {request_bytes} bytes")
                    consecutive_failures += 1
                    if ladder_idx < len(ladder) - 1:
                        ladder_idx += 1
                    if consecutive_failures >= SPEED_MAX_CONSECUTIVE_FAILURES:
                        failed = True
                        break
                    _sleep_brief(deadline, consecutive_failures)
                    continue
                note_error(f"{direction}: HTTP {result.status}")
                failed = True
                break
        finally:
            try:
                conn.close()
            except Exception:
                pass
            with lock:
                state["connections"] += getattr(conn, "connections_made", 0)
                if failed:
                    state["workers_failed"] += 1

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(max(1, parallel))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=duration_s + 20)
    elapsed = time.monotonic() - start
    cap_hit = state["total"] >= SPEED_MAX_TOTAL_BYTES

    first_steady_bucket = math.ceil(warmup_s / SPEED_BUCKET_SECONDS) \
        if warmup_s > 0 else 0
    steady_bytes = sum(n for idx, n in buckets.items() if idx >= first_steady_bucket)
    measured_s = max(0.0, elapsed - warmup_s)
    full_bucket_rates = []
    last_bucket_idx = int(elapsed / SPEED_BUCKET_SECONDS)
    for idx, n in buckets.items():
        if idx >= first_steady_bucket and idx < last_bucket_idx:
            full_bucket_rates.append(n * 8 / SPEED_BUCKET_SECONDS / 1_000_000)
    p90 = _nearest_rank(full_bucket_rates, 90)
    ended_early = elapsed < duration_s * SPEED_MIN_COMPLETE_RATIO and not cap_hit
    reliable = bool(steady_bytes > 0 and not ended_early
                    and state["workers_failed"] == 0)
    incomplete_reason = None
    if ended_early:
        incomplete_reason = (f"{direction} phase ended after "
                             f"{round(elapsed, 2)}s of {round(duration_s, 2)}s")
    elif state["workers_failed"]:
        incomplete_reason = (f"{state['workers_failed']} {direction} stream(s) "
                             "gave up after repeated failures")
    return {
        "total_bytes": state["total"],
        "steady_bytes": steady_bytes,
        "elapsed_s": elapsed,
        "measured_s": measured_s,
        "warmup_s": warmup_s,
        "mbps": round(steady_bytes * 8 / measured_s / 1_000_000, 2)
                 if steady_bytes > 0 and measured_s > 0 else None,
        "p90_mbps": round(p90, 2) if p90 is not None else None,
        "cap_hit": cap_hit,
        "ended_early": ended_early,
        "reliable": reliable,
        "incomplete_reason": incomplete_reason,
        "errors": errors,
        "requests": state["requests"],
        "completed_requests": state["completed_requests"],
        "connections": state["connections"],
        "workers_failed": state["workers_failed"],
        "colo": state["colo"],
    }


def _sleep_brief(deadline: float, failures: int) -> None:
    """Short retry backoff that never sleeps past the phase deadline."""
    target = min(deadline, time.monotonic() + 0.2 * max(1, failures))
    while time.monotonic() < target:
        time.sleep(min(0.05, max(0.0, target - time.monotonic())))


def run_speed_test(download_s: float = SPEED_DOWNLOAD_SECONDS,
                   upload_s: float = SPEED_UPLOAD_SECONDS,
                   parallel: int = SPEED_PARALLEL_STREAMS,
                   probe_fn=None, transport_factory=None,
                   warmup_s: float = SPEED_WARMUP_SECONDS,
                   host: str = SPEED_HOST, port: int = 443,
                   use_tls: bool = True) -> dict:
    """Sustained throughput via Cloudflare's public speed endpoints.

    Each worker holds one persistent connection and streams large
    back-to-back transfers for the whole phase (25s down, 20s up by
    default); bytes are bucketed as they move and the first ~2s of
    slow-start buckets are dropped from the headline. Failures retry
    with smaller requests and are reported, never swallowed: a phase
    that ends early or loses a stream comes back flagged unreliable,
    and callers must not grade it against a plan. While the download
    saturates the link, latency probes keep running so the result also
    carries a bufferbloat grade. transport_factory is injectable for
    tests; host/port/use_tls point the real transport at a local test
    server."""
    probe_fn = probe_fn or probe_target
    if transport_factory is None:
        def transport_factory():  # noqa: F811 - default real transport
            return _CloudflareConnection(host=host, port=port, use_tls=use_tls)
    download_s = max(0.05, min(float(download_s), 60.0))
    upload_s = max(0.05, min(float(upload_s), 60.0))
    out: dict = {"ok": False,
                 "note": "Sustained multi-stream test over persistent connections. "
                         "Still an estimate on very fast lines; latency graphs will "
                         "spike while this runs, which is the test, not an outage."}

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

    prober_thread = threading.Thread(target=loaded_prober, daemon=True)
    prober_thread.start()
    try:
        down = _run_phase(download_s, parallel, transport_factory,
                          "download", warmup_s)
    finally:
        loaded_stop.set()
        prober_thread.join(timeout=5)
    out["download_seconds"] = round(down["elapsed_s"], 2)
    out["download_measured_seconds"] = round(down["measured_s"], 2)
    out["warmup_seconds"] = round(down["warmup_s"], 2)
    out["cap_hit"] = down["cap_hit"]
    out["loaded_latency_ms"] = _median_or_none(loaded_values)
    if out["idle_latency_ms"] is not None and out["loaded_latency_ms"] is not None:
        out["bufferbloat_ms"] = round(out["loaded_latency_ms"] - out["idle_latency_ms"], 2)
    else:
        out["bufferbloat_ms"] = None
    out["bufferbloat_grade"] = bufferbloat_grade(out["bufferbloat_ms"])
    out["download_mbps"] = down["mbps"]
    out["download_bytes"] = down["total_bytes"]
    out["download_steady_bytes"] = down["steady_bytes"]
    out["download_p90_mbps"] = down["p90_mbps"]
    out["download_requests"] = down["requests"]
    out["download_completed_requests"] = down["completed_requests"]
    out["download_connections"] = down["connections"]
    out["download_errors"] = down["errors"]
    out["download_reliable"] = down["reliable"]
    out["speed_colo"] = down["colo"]
    if down["mbps"] is None:
        out["error"] = ("Download test got no usable data. "
                        + ("; ".join(down["errors"]) if down["errors"] else ""))
        out["reliable"] = False
        out["complete"] = False
        return out

    up = _run_phase(upload_s, parallel, transport_factory, "upload", warmup_s)
    out["upload_seconds"] = round(up["elapsed_s"], 2)
    out["upload_measured_seconds"] = round(up["measured_s"], 2)
    out["cap_hit"] = bool(out.get("cap_hit") or up["cap_hit"])
    if out["cap_hit"]:
        out["note"] += " The safety data cap was hit, so a phase ended early."
    out["upload_mbps"] = up["mbps"]
    out["upload_bytes"] = up["total_bytes"]
    out["upload_steady_bytes"] = up["steady_bytes"]
    out["upload_p90_mbps"] = up["p90_mbps"]
    out["upload_requests"] = up["requests"]
    out["upload_completed_requests"] = up["completed_requests"]
    out["upload_connections"] = up["connections"]
    out["upload_errors"] = up["errors"]
    out["upload_reliable"] = up["reliable"]
    out["speed_colo"] = out.get("speed_colo") or up["colo"]
    out["data_used_bytes"] = down["total_bytes"] + up["total_bytes"]

    reasons = [r for r in (down["incomplete_reason"], up["incomplete_reason"]) if r]
    out["complete"] = not reasons
    out["reliable"] = bool(down["reliable"] and up["reliable"])
    if up["mbps"] is None:
        out["error"] = ("Upload test sent no usable data. Download result above "
                        "still counts." + (" " + "; ".join(up["errors"])
                                            if up["errors"] else ""))
    elif reasons:
        out["error"] = ("Test incomplete: " + "; ".join(reasons)
                        + ". Numbers are provisional, not plan evidence.")
    out["ok"] = True
    return out

"""URL validation, ping-output parsing, probe fallback, HTTP check, speed test."""
import http.server
import threading
import time
import urllib.parse

import pytest

from network_monitor import prober
from network_monitor.prober import (ProbeResult, bufferbloat_grade, parse_ping_ms,
                                    parse_url, run_speed_test)


def test_parse_ping_windows_and_linux():
    assert parse_ping_ms("Reply from 1.1.1.1: bytes=32 time=12ms TTL=57") == 12.0
    assert parse_ping_ms("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=7.42 ms") == 7.42
    assert parse_ping_ms("Request timed out.") is None
    assert parse_ping_ms("") is None


def test_parse_url_variants():
    p = parse_url("https://example.com/path?q=1")
    assert (p.scheme, p.host, p.port, p.path) == ("https", "example.com", 443, "/path?q=1")
    p = parse_url("example.com")
    assert (p.scheme, p.host, p.port) == ("https", "example.com", 443)
    p = parse_url("http://192.168.1.50:8080/x")
    assert (p.host, p.port, p.path) == ("192.168.1.50", 8080, "/x")
    assert p.url == "http://192.168.1.50:8080/x"
    # Non-default scheme/port combos keep the port in the normalized URL.
    assert parse_url("http://example.com:443/x").url == "http://example.com:443/x"
    assert parse_url("https://example.com:443/x").url == "https://example.com/x"


@pytest.mark.parametrize("bad", [
    "", "   ", "ftp://example.com", "https://user:pass@example.com",
    "https://exa mple.com", "https://", "http://example.com:99999",
    "http://bad_host!.example", "https://[::1]/",
])
def test_parse_url_rejects(bad):
    with pytest.raises(ValueError):
        parse_url(bad)


def test_probe_target_ping_first(monkeypatch):
    monkeypatch.setattr(prober, "ping_latency",
                        lambda host, timeout_s=1.0: ProbeResult(True, 5.0, "ping"))
    monkeypatch.setattr(prober, "tcp_latency",
                        lambda host, port, timeout_s=1.5: ProbeResult(True, 9.0, "tcp"))
    result = prober.probe_target("1.1.1.1", 443)
    assert result.ok and result.method == "ping" and result.ms == 5.0


def test_probe_target_tcp_fallback(monkeypatch):
    monkeypatch.setattr(prober, "ping_latency",
                        lambda host, timeout_s=1.0: ProbeResult(False, None, "ping"))
    monkeypatch.setattr(prober, "tcp_latency",
                        lambda host, port, timeout_s=1.5: ProbeResult(True, 9.0, "tcp"))
    result = prober.probe_target("1.1.1.1", 443)
    assert result.ok and result.method == "tcp"


def test_probe_gateway_uses_any_common_port(monkeypatch):
    monkeypatch.setattr(prober, "ping_latency",
                        lambda host, timeout_s=1.0: ProbeResult(False, None, "ping"))
    tried = []

    def fake_tcp(host, port, timeout_s=1.5):
        tried.append(port)
        return ProbeResult(port == 443, 7.0 if port == 443 else None, "tcp")

    monkeypatch.setattr(prober, "tcp_latency", fake_tcp)
    result = prober.probe_gateway("192.168.1.1")
    assert result.ok and result.ms == 7.0
    assert tried[:2] == [80, 443]  # stopped at the first port that answered


def test_probe_gateway_all_ports_fail(monkeypatch):
    monkeypatch.setattr(prober, "ping_latency",
                        lambda host, timeout_s=1.0: ProbeResult(False, None, "ping"))
    monkeypatch.setattr(prober, "tcp_latency",
                        lambda host, port, timeout_s=1.5: ProbeResult(False, None, "tcp"))
    result = prober.probe_gateway("172.25.214.1")
    assert not result.ok and result.method == "none"


def test_probe_target_both_fail(monkeypatch):
    monkeypatch.setattr(prober, "ping_latency",
                        lambda host, timeout_s=1.0: ProbeResult(False, None, "ping"))
    monkeypatch.setattr(prober, "tcp_latency",
                        lambda host, port, timeout_s=1.5: ProbeResult(False, None, "tcp", "refused"))
    result = prober.probe_target("1.1.1.1", 443)
    assert not result.ok and result.ms is None


def test_http_check_bad_dns():
    parsed = parse_url("https://nonexistent.invalid.example")
    result = prober.http_check(parsed, timeout_s=3.0)
    assert result["ok"] is False
    assert "error" in result


def test_bufferbloat_grades():
    assert bufferbloat_grade(None) is None
    assert bufferbloat_grade(3) == "A+"
    assert bufferbloat_grade(10) == "A"
    assert bufferbloat_grade(25) == "B"
    assert bufferbloat_grade(50) == "C"
    assert bufferbloat_grade(100) == "D"
    assert bufferbloat_grade(300) == "F"


class _KnownRateTransport:
    """Fake transport that moves bytes at a fixed, known rate.

    This is the accuracy check the old suite never had: the fake
    delivers bytes at a simulated line rate, so the engine's headline
    must land near that rate — not merely above zero."""

    def __init__(self, bytes_per_second: float, fail_status: int | None = None):
        self.rate = bytes_per_second
        self.fail_status = fail_status
        self.connections_made = 1
        self.colo = "TST"
        self.request_sizes: list[int] = []

    def _move(self, request_bytes, should_run, on_chunk):
        if self.fail_status is not None:
            return prober._TransferResult(self.fail_status, 0, False)
        moved = 0
        chunk = 65_536
        while moved < request_bytes and should_run():
            n = min(chunk, request_bytes - moved)
            time.sleep(n / self.rate)
            moved += n
            on_chunk(n)
        return prober._TransferResult(200, moved, moved >= request_bytes)

    def download(self, request_bytes, deadline, should_run, on_chunk):
        self.request_sizes.append(request_bytes)
        return self._move(request_bytes, should_run, on_chunk)

    def upload(self, request_bytes, deadline, should_run, on_chunk):
        self.request_sizes.append(request_bytes)
        return self._move(request_bytes, should_run, on_chunk)

    def close(self):
        pass


def _fake_probe_factory():
    calls = {"n": 0}
    lock = threading.Lock()

    def fake_probe(host, port):
        with lock:
            calls["n"] += 1
            n = calls["n"]
        # First three probes are the idle baseline; loaded probes read higher.
        return ProbeResult(True, 10.0 if n <= 3 else 30.0, "ping")

    return fake_probe


def test_speed_test_defaults_are_sustained():
    # Short bursts mostly measure TCP slow-start. The defaults must be
    # long, settled phases (research: 20-30s class, warmup discarded).
    assert prober.SPEED_DOWNLOAD_SECONDS >= 20
    assert prober.SPEED_UPLOAD_SECONDS >= 15
    assert prober.SPEED_WARMUP_SECONDS >= 1
    # Large requests over reused connections; tiny per-request payloads
    # pay a fresh handshake each time and cap the measured speed.
    assert prober.SPEED_DOWNLOAD_REQUEST_BYTES >= 10_000_000
    assert prober.SPEED_UPLOAD_REQUEST_BYTES >= 1_000_000


def test_speed_test_accuracy_against_known_rate():
    per_stream = 2_500_000  # bytes/s per stream = 20 Mbps
    result = run_speed_test(
        download_s=1.5, upload_s=1.5, parallel=2,
        probe_fn=_fake_probe_factory(),
        transport_factory=lambda: _KnownRateTransport(per_stream),
        warmup_s=0.3)
    assert result["ok"] is True
    assert result["reliable"] is True and result["complete"] is True
    expected_mbps = per_stream * 2 * 8 / 1_000_000  # 40 Mbps aggregate
    assert result["download_mbps"] == pytest.approx(expected_mbps, rel=0.2)
    assert result["upload_mbps"] == pytest.approx(expected_mbps, rel=0.2)
    assert result["data_used_bytes"] == result["download_bytes"] + result["upload_bytes"]
    assert result["idle_latency_ms"] == 10.0
    assert result["loaded_latency_ms"] == 30.0
    assert result["bufferbloat_ms"] == 20.0
    assert result["bufferbloat_grade"] == "B"
    assert result["download_measured_seconds"] < result["download_seconds"]
    assert result["download_connections"] == 2  # one per worker, reused


def test_speed_test_early_failure_is_surfaced_not_graded():
    # Every request refused (the old test swallowed this and graded a
    # partial phase): the phase must end early, flag itself
    # unreliable, and say why.
    result = run_speed_test(
        download_s=3.0, upload_s=0.5, parallel=2,
        probe_fn=_fake_probe_factory(),
        transport_factory=lambda: _KnownRateTransport(1_000_000, fail_status=429),
        warmup_s=0.3)
    assert result["ok"] is False
    assert result["download_mbps"] is None
    assert result["reliable"] is False and result["complete"] is False
    assert "429" in result["error"]


def test_speed_test_partial_phase_is_unreliable():
    # A transport that dies with an exception on every attempt after
    # moving a few bytes: some data arrives, but the phase can never
    # complete at full stream count, so it must not read as reliable.
    class _DyingTransport(_KnownRateTransport):
        def _move(self, request_bytes, should_run, on_chunk):
            on_chunk(65_536)
            raise prober._SpeedTransportError("connection reset")

    result = run_speed_test(
        download_s=2.0, upload_s=0.5, parallel=2,
        probe_fn=_fake_probe_factory(),
        transport_factory=lambda: _DyingTransport(1_000_000),
        warmup_s=0.2)
    assert result["download_reliable"] is False
    assert result["download_errors"]  # recorded, not swallowed


def test_speed_test_upload_aborted_by_deadline_is_not_a_failure():
    # The normal end of every upload phase: the deadline lands while
    # a large post is still in flight and the transport aborts it with
    # no status. That must not mark the stream failed/unreliable.
    class _DeadlineAbortUpload(_KnownRateTransport):
        def upload(self, request_bytes, deadline, should_run, on_chunk):
            moved = 0
            while should_run():
                on_chunk(65_536)
                moved += 65_536
                time.sleep(0.01)
            return prober._TransferResult(None, moved, False)

    result = run_speed_test(
        download_s=0.6, upload_s=0.6, parallel=2,
        probe_fn=_fake_probe_factory(),
        transport_factory=lambda: _DeadlineAbortUpload(2_500_000),
        warmup_s=0.15)
    assert result["ok"] is True
    assert result["upload_mbps"] is not None
    assert result["upload_reliable"] is True
    assert result["upload_errors"] == []


class _LocalSpeedHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    connections_seen: set = set()

    def log_message(self, fmt, *args):
        pass

    def _note_conn(self):
        type(self).connections_seen.add(self.client_address)

    def do_GET(self):
        self._note_conn()
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        total = int(query.get("bytes", ["0"])[0])
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(total))
        self.end_headers()
        block = b"x" * 65_536
        sent = 0
        while sent < total:
            part = block if total - sent >= len(block) else block[:total - sent]
            try:
                self.wfile.write(part)
            except (BrokenPipeError, ConnectionResetError):
                return
            sent += len(part)

    def do_POST(self):
        self._note_conn()
        remaining = int(self.headers.get("Content-Length") or 0)
        while remaining > 0:
            chunk = self.rfile.read(min(65_536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_speed_test_real_transport_reuses_connections():
    # Real http.client transport against a local server: each worker
    # must open exactly one connection per phase and reuse it across
    # back-to-back requests (the old code paid a TLS handshake per
    # small request).
    _LocalSpeedHandler.connections_seen = set()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LocalSpeedHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        result = run_speed_test(
            download_s=1.2, upload_s=1.2, parallel=2,
            probe_fn=_fake_probe_factory(),
            host="127.0.0.1", port=port, use_tls=False, warmup_s=0.2)
    finally:
        server.shutdown()
        server.server_close()
    assert result["ok"] is True
    assert result["download_mbps"] and result["download_mbps"] > 0
    assert result["upload_mbps"] and result["upload_mbps"] > 0
    assert result["download_connections"] == 2
    assert result["upload_connections"] == 2
    assert result["download_completed_requests"] >= 2
    assert result["upload_completed_requests"] >= 2

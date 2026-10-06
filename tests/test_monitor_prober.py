"""URL validation, ping-output parsing, probe fallback, HTTP check, speed test."""
import threading

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


class _FakeResp:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    def read(self, n=-1):
        return self._chunks.pop(0) if self._chunks else b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_speed_test_timed_with_fakes():
    calls = {"n": 0}
    lock = threading.Lock()

    def fake_probe(host, port):
        with lock:
            calls["n"] += 1
            n = calls["n"]
        # First three probes are the idle baseline; the loaded probes
        # during the download read higher.
        return ProbeResult(True, 10.0 if n <= 3 else 30.0, "ping")

    def fake_urlopen(req, timeout=None):
        url = req.full_url
        if "__down" in url:
            return _FakeResp([b"x" * 4096])
        return _FakeResp([b""])

    result = run_speed_test(download_s=0.25, upload_s=0.25, parallel=2,
                            probe_fn=fake_probe, urlopen_fn=fake_urlopen)
    assert result["ok"] is True
    assert result["download_bytes"] > 0 and result["download_mbps"] > 0
    assert result["upload_bytes"] > 0 and result["upload_mbps"] > 0
    assert result["download_seconds"] >= 0.2
    assert result["data_used_bytes"] == result["download_bytes"] + result["upload_bytes"]
    assert result["idle_latency_ms"] == 10.0
    assert result["loaded_latency_ms"] == 30.0
    assert result["bufferbloat_ms"] == 20.0
    assert result["bufferbloat_grade"] == "B"

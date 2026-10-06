"""URL validation, ping-output parsing, probe fallback, HTTP check."""
import pytest

from network_monitor import prober
from network_monitor.prober import ProbeResult, parse_ping_ms, parse_url


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

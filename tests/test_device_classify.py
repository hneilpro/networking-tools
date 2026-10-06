"""Device classification, incl. the ping-only noise filter (no real network)."""
from rdp_troubleshooter import scanner
from rdp_troubleshooter.diagnostics import TcpResult


def _probe(monkeypatch, *, ping_ok, states, hostname):
    monkeypatch.setattr(scanner, "ping_host", lambda ip, timeout_s=1: (ping_ok, ""))
    monkeypatch.setattr(scanner, "tcp_check",
                        lambda ip, port, timeout=0.9: TcpResult(port, states.get(port, "filtered")))
    monkeypatch.setattr(scanner, "resolve_hostname", lambda ip: hostname)
    return scanner._probe_host("192.168.1.50", {}, "192.168.1.2")


def test_ping_only_device_is_flagged(monkeypatch):
    d = _probe(monkeypatch, ping_ok=True, states={}, hostname=None)
    assert d is not None and d["ping_only"] is True


def test_device_with_open_port_is_not_ping_only(monkeypatch):
    d = _probe(monkeypatch, ping_ok=True, states={3389: "open"}, hostname=None)
    assert d["ping_only"] is False and d["rdp_ready"] is True


def test_named_device_is_not_ping_only(monkeypatch):
    d = _probe(monkeypatch, ping_ok=True, states={}, hostname="DESKTOP-ABC")
    assert d["ping_only"] is False


def test_dead_device_is_dropped(monkeypatch):
    d = _probe(monkeypatch, ping_ok=False, states={}, hostname=None)
    assert d is None

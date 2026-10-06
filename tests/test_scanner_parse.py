"""Scanner parsing tests that don't need a live network."""
import subprocess

from rdp_troubleshooter import scanner


def test_read_arp_cache_tolerates_missing_binary(monkeypatch):
    def boom(*a, **k):
        raise OSError("no arp binary")
    monkeypatch.setattr(subprocess, "run", boom)
    assert scanner.read_arp_cache() == {}


def test_detect_network_shape():
    info = scanner.detect_network()
    assert set(info) == {"local_ip", "subnet", "gateway_hint"}
    if info["local_ip"]:
        assert info["subnet"].endswith("/24")


def test_port_names_cover_scan_ports():
    for port in scanner.SCAN_PORTS:
        assert port in scanner.PORT_NAMES

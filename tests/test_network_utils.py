import pytest

from rdp_troubleshooter.network_utils import (
    classify_ip, is_cgnat_ip, parse_gateway_ip_route,
    parse_gateway_mac_route_get, parse_gateway_netstat,
    parse_gateway_proc_net_route, parse_gateway_windows_route_print,
    parse_port, parse_target, validate_scan_cidr,
)


def test_parse_target_accepts_ip_and_hostname():
    assert parse_target(" 192.168.1.42 ") == "192.168.1.42"
    assert parse_target("DESKTOP-ABC123") == "desktop-abc123"
    assert parse_target("my-pc.local") == "my-pc.local"


@pytest.mark.parametrize("bad", ["", "  ", "bad host", "192.168.1.1/24", "a" * 300,
                                 "pc\\share", "-bad-", "bad..name"])
def test_parse_target_rejects_garbage(bad):
    with pytest.raises(ValueError):
        parse_target(bad)


def test_parse_port():
    assert parse_port(3389) == 3389
    assert parse_port("3390") == 3390
    for bad in (0, 65536, "abc", None):
        with pytest.raises(ValueError):
            parse_port(bad)


def test_classify_ip():
    assert classify_ip("192.168.1.10") == "lan"
    assert classify_ip("10.0.0.5") == "lan"
    assert classify_ip("100.64.0.1") == "lan"
    assert classify_ip("8.8.8.8") == "internet"
    assert classify_ip("127.0.0.1") == "local"


def test_cgnat():
    assert is_cgnat_ip("100.64.0.1")
    assert is_cgnat_ip("100.127.255.254")
    assert not is_cgnat_ip("100.128.0.1")
    assert not is_cgnat_ip("192.168.1.1")


def test_parse_gateway_windows_route_print():
    text = (
        "IPv4 Route Table\n"
        "Active Routes:\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\n"
        "          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.42     25\n"
        "        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331\n"
    )
    assert parse_gateway_windows_route_print(text) == "192.168.1.1"
    assert parse_gateway_windows_route_print("no routes here") is None


def test_parse_gateway_linux_and_mac_outputs():
    assert parse_gateway_ip_route(
        "default via 172.25.214.1 dev eth0 proto dhcp metric 100\n") == "172.25.214.1"
    assert parse_gateway_ip_route("10.0.0.0/24 dev eth0\n") is None
    # /proc/net/route: gateway hex is little-endian (0101A8C0 = 192.168.1.1).
    proc = ("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
            "eth0 00000000 0101A8C0 0003 0 0 100 00000000 0 0 0\n")
    assert parse_gateway_proc_net_route(proc) == "192.168.1.1"
    assert parse_gateway_mac_route_get(
        "   route to: default\n    gateway: 192.168.1.254\n") == "192.168.1.254"
    assert parse_gateway_netstat(
        "0.0.0.0            192.168.1.1        0.0.0.0            UG\n") == "192.168.1.1"
    assert parse_gateway_netstat("") is None


def test_validate_scan_cidr_private_only_and_size_capped():
    assert str(validate_scan_cidr("192.168.1.0/24")) == "192.168.1.0/24"
    assert str(validate_scan_cidr("192.168.1.42/24")) == "192.168.1.0/24"
    with pytest.raises(ValueError):
        validate_scan_cidr("8.8.8.0/24")       # public: refused
    with pytest.raises(ValueError):
        validate_scan_cidr("10.0.0.0/8")       # too large
    with pytest.raises(ValueError):
        validate_scan_cidr("not-a-network")

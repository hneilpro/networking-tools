import pytest

from rdp_troubleshooter.network_utils import (
    classify_ip, is_cgnat_ip, parse_port, parse_target, validate_scan_cidr,
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


def test_validate_scan_cidr_private_only_and_size_capped():
    assert str(validate_scan_cidr("192.168.1.0/24")) == "192.168.1.0/24"
    assert str(validate_scan_cidr("192.168.1.42/24")) == "192.168.1.0/24"
    with pytest.raises(ValueError):
        validate_scan_cidr("8.8.8.0/24")       # public: refused
    with pytest.raises(ValueError):
        validate_scan_cidr("10.0.0.0/8")       # too large
    with pytest.raises(ValueError):
        validate_scan_cidr("not-a-network")

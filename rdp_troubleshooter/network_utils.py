"""Network helpers: validation, subnet math, and reachability context.

Stdlib only. No user input is ever passed to a shell.
"""
from __future__ import annotations

import ipaddress
import os
import platform
import re
import socket
import subprocess

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

MAX_TARGET_LEN = 253
MAX_SCAN_HOSTS = 256  # one /24


def parse_target(raw: str) -> str:
    """Validate and normalize a user-supplied IP or hostname.

    Raises ValueError with a user-facing message on bad input.
    """
    if raw is None:
        raise ValueError("Enter a target PC name or IP address.")
    target = str(raw).strip()
    if not target:
        raise ValueError("Enter a target PC name or IP address.")
    if len(target) > MAX_TARGET_LEN:
        raise ValueError("That target is too long to be a valid name or IP.")
    if any(ch.isspace() for ch in target) or "/" in target or "\\" in target:
        raise ValueError("Enter just a PC name or IP address, no paths or spaces.")
    # Strip an optional :port suffix is NOT done here; the UI sends port separately.
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(target):
        raise ValueError("That doesn't look like a valid PC name or IP address.")
    return target.lower()


def parse_port(raw, default: int = 3389) -> int:
    try:
        port = int(raw)
    except (TypeError, ValueError):
        raise ValueError("Port must be a number between 1 and 65535.")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    return port


def resolve_target(target: str) -> tuple[str | None, str | None]:
    """Return (ipv4, error). Hostnames resolve to their first IPv4 address."""
    try:
        ip = ipaddress.ip_address(target)
        if ip.version != 4:
            return None, "IPv6 targets aren't supported by this tool yet. Use the IPv4 address."
        return str(ip), None
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return None, f"Could not resolve '{target}'. Check the PC name, or use its IP address instead."
    if not infos:
        return None, f"Could not resolve '{target}'."
    return infos[0][4][0], None


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_cgnat_ip(ip: str) -> bool:
    """100.64.0.0/10 is carrier-grade NAT space (RFC 6598)."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return False


_LAN_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "100.64.0.0/10",   # CGNAT
    "169.254.0.0/16",  # link-local
))


def classify_ip(ip: str) -> str:
    """'lan' for private/CGNAT space, 'internet' for public, 'local' for loopback.

    Uses an explicit LAN list: ipaddress.is_private also flags documentation
    ranges (192.0.2.0/24 etc.), which are not LAN addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "local"
    if any(addr in net for net in _LAN_NETS):
        return "lan"
    return "internet"


def _valid_gateway(candidate: str | None) -> str | None:
    if not candidate:
        return None
    try:
        addr = ipaddress.ip_address(str(candidate).strip())
    except ValueError:
        return None
    if addr.version != 4 or str(addr) == "0.0.0.0":
        return None
    return str(addr)


def parse_gateway_windows_route_print(text: str) -> str | None:
    """Parse `route print -4` output: the gateway column of the 0.0.0.0 route."""
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            gateway = _valid_gateway(parts[2])
            if gateway:
                return gateway
    return None


def parse_gateway_ip_route(text: str) -> str | None:
    """Parse `ip route show default`, e.g. 'default via 192.168.1.1 dev eth0 ...'."""
    match = re.search(r"^default\s+via\s+(\S+)", text or "", re.MULTILINE)
    return _valid_gateway(match.group(1)) if match else None


def parse_gateway_proc_net_route(text: str) -> str | None:
    """/proc/net/route: destination 00000000, gateway as little-endian hex."""
    for line in (text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "00000000":
            try:
                raw = bytes.fromhex(parts[2])
            except ValueError:
                continue
            if len(raw) == 4:
                gateway = _valid_gateway(".".join(str(b) for b in reversed(raw)))
                if gateway:
                    return gateway
    return None


def parse_gateway_mac_route_get(text: str) -> str | None:
    """Parse macOS `route -n get default`, which prints a 'gateway:' line."""
    match = re.search(r"^\s*gateway:\s*(\S+)", text or "", re.MULTILINE)
    return _valid_gateway(match.group(1)) if match else None


def parse_gateway_netstat(text: str) -> str | None:
    """Parse `netstat -rn`: default/0.0.0.0 route, gateway is column two."""
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "default"):
            gateway = _valid_gateway(parts[1])
            if gateway:
                return gateway
    return None


def _run_text(cmd: list[str], timeout_s: float = 3.0) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout or ""


def default_gateway() -> str | None:
    """The OS's real default gateway IPv4, from the routing table.

    Best-effort and never raises: guessing '.1' is a fallback the caller
    makes, not something this function pretends is measured fact."""
    system = platform.system().lower()
    try:
        if system == "windows":
            return (parse_gateway_windows_route_print(_run_text(["route", "print", "-4"]))
                    or parse_gateway_netstat(_run_text(["netstat", "-rn"])))
        if system == "darwin":
            return (parse_gateway_mac_route_get(_run_text(["route", "-n", "get", "default"]))
                    or parse_gateway_netstat(_run_text(["netstat", "-rn"])))
        # Linux and anything else with iproute2 / procfs.
        gateway = parse_gateway_ip_route(_run_text(["ip", "route", "show", "default"]))
        if gateway:
            return gateway
        try:
            with open("/proc/net/route", encoding="utf-8", errors="replace") as handle:
                return parse_gateway_proc_net_route(handle.read())
        except OSError:
            return None
    except Exception:  # a routing-table surprise must never break the tools
        return None


def is_wsl() -> bool:
    """True when running inside Windows Subsystem for Linux.

    There the 'gateway' is the Windows host's virtual NAT, not the
    physical router, which changes what gateway probes can prove."""
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSLENV"):
        return True
    try:
        if "microsoft" in platform.uname().release.lower():
            return True
    except Exception:
        pass
    try:
        with open("/proc/sys/kernel/osrelease", encoding="utf-8", errors="replace") as handle:
            return "microsoft" in handle.read().lower()
    except OSError:
        return False


def local_ipv4() -> str | None:
    """Best-effort local IPv4. UDP connect sends no traffic; it only picks a route."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        pass
    finally:
        sock.close()
    try:
        return socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        return None


def subnet_for(ip: str, prefix: int = 24) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)


def same_subnet(ip_a: str, ip_b: str, prefix: int = 24) -> bool | None:
    try:
        return subnet_for(ip_a, prefix) == subnet_for(ip_b, prefix)
    except ValueError:
        return None


def validate_scan_cidr(raw: str) -> ipaddress.IPv4Network:
    """Only private IPv4 networks of /24 or smaller may be scanned."""
    try:
        net = ipaddress.ip_network(str(raw).strip(), strict=False)
    except ValueError:
        raise ValueError("Enter a network like 192.168.1.0/24.")
    if net.version != 4:
        raise ValueError("Only IPv4 networks can be scanned.")
    if not net.is_private:
        raise ValueError("For safety, this tool only scans private (home/office) networks.")
    if net.num_addresses > MAX_SCAN_HOSTS:
        raise ValueError("That network is too large to scan. Use a /24 or smaller (max 254 PCs).")
    return net

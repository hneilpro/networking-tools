"""Local network scanner: finds live devices and flags likely Windows PCs.

Safety rails: private IPv4 only, /24 max (enforced in network_utils),
thread-pooled with short timeouts, and the server only starts a scan when
the user explicitly asks.
"""
from __future__ import annotations

import ipaddress
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

from .diagnostics import WINDOWS_HINT_PORTS, RDP_PORT, ping_host, tcp_check
from .network_utils import default_gateway, is_wsl, local_ipv4, subnet_for

SCAN_PORTS = (RDP_PORT, 445, 135, 139, 80, 443)
PORT_NAMES = {3389: "RDP", 445: "SMB", 135: "MSRPC", 139: "NetBIOS", 80: "HTTP", 443: "HTTPS"}


def read_arp_cache() -> dict[str, str]:
    """ip -> MAC from the OS ARP cache. Best-effort, never raises."""
    table: dict[str, str] = {}
    try:
        proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return table
    for line in proc.stdout.splitlines():
        parts = line.replace("(", " ").replace(")", " ").replace("-", ":").split()
        ip = mac = None
        for part in parts:
            try:
                ip = str(ipaddress.ip_address(part))
                continue
            except ValueError:
                pass
            if part.count(":") == 5 and len(part) == 17:
                mac = part.lower()
        if ip and mac and mac != "ff:ff:ff:ff:ff:ff":
            table[ip] = mac
    return table


def resolve_hostname(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None
    return name if name and name != ip else None


def detect_network() -> dict:
    ip = local_ipv4()
    gateway = default_gateway() if ip else None
    gateway_source = "route" if gateway else None
    if ip and not gateway:
        # Routing-table lookup failed: '.1' is the usual home-router
        # address, but it is a guess and is labelled as one downstream.
        octets = ip.split(".")
        gateway = ".".join(octets[:3] + ["1"])
        gateway_source = "guess"
    wsl = is_wsl()
    info = {"local_ip": ip, "subnet": None, "gateway_hint": gateway,
            "gateway_source": gateway_source,
            "environment": "wsl" if wsl else "native",
            # Under WSL the default gateway is the Windows host's virtual
            # NAT interface, not the physical router on the LAN.
            "gateway_is_virtual": bool(wsl and gateway)}
    if ip:
        info["subnet"] = str(subnet_for(ip, 24))
    return info


def _probe_host(ip: str, arp: dict[str, str], local_ip: str | None) -> dict | None:
    """Return a device dict if the host shows any sign of life, else None."""
    ping_ok, _ = ping_host(ip, timeout_s=1)
    results = {p: tcp_check(ip, p, timeout=0.9) for p in SCAN_PORTS}
    open_ports = [p for p, r in results.items() if r.state == "open"]
    answered = ping_ok or any(r.state in ("open", "refused") for r in results.values())
    if not answered:
        return None
    hostname = resolve_hostname(ip)
    windows_ports = [p for p in WINDOWS_HINT_PORTS if results[p].state == "open"]
    windows_likely = bool(windows_ports) or (hostname is not None and hostname.upper().startswith("DESKTOP-"))
    return {
        "ip": ip,
        "hostname": hostname,
        "mac": arp.get(ip),
        "ping": ping_ok,
        "open_ports": [{"port": p, "name": PORT_NAMES.get(p, "")} for p in open_ports],
        "windows_likely": windows_likely,
        "rdp_ready": results[RDP_PORT].state == "open",
        "is_this_pc": ip == local_ip,
        # Only a ping reply, with no name/MAC/open port, is weak evidence:
        # some routers/VPNs answer ping for every address. The UI hides these.
        "ping_only": bool(ping_ok and not open_ports and not hostname),
    }


def scan_network(network: ipaddress.IPv4Network, max_workers: int = 48) -> list[dict]:
    """Scan a validated private network (<= /24). Returns live devices, sorted."""
    local_ip = local_ipv4()
    # Prime the ARP cache with the sweep itself, then read it back.
    hosts = [str(h) for h in network.hosts()] or [str(network.network_address)]
    arp_before = read_arp_cache()
    devices: list[dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for device in pool.map(lambda ip: _probe_host(ip, arp_before, local_ip), hosts):
            if device:
                devices.append(device)
    arp_after = read_arp_cache()
    for device in devices:
        if not device["mac"]:
            device["mac"] = arp_after.get(device["ip"])
    devices.sort(key=lambda d: tuple(int(o) for o in d["ip"].split(".")))
    return devices

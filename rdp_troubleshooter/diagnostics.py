"""RDP diagnostic checks and the verdict engine.

The verdict logic is pure (inputs are check results) so it can be unit
tested without touching a real network.
"""
from __future__ import annotations

import platform
import socket
import subprocess
import time
from dataclasses import dataclass, field

from .network_utils import classify_ip, is_cgnat_ip, resolve_target, same_subnet

RDP_PORT = 3389
WINDOWS_HINT_PORTS = (135, 139, 445)  # MSRPC, NetBIOS, SMB: alive => very likely Windows
PROBE_TIMEOUT = 2.0


@dataclass
class TcpResult:
    port: int
    state: str  # "open" | "refused" | "filtered" | "error"
    detail: str = ""
    ms: int | None = None


@dataclass
class Diagnosis:
    target: str
    resolved_ip: str | None = None
    steps: list = field(default_factory=list)
    verdict_code: str = "unknown"
    verdict_title: str = ""
    likely_cause: str = ""
    confidence: str = "low"
    fix_steps: list = field(default_factory=list)
    target_checks: list = field(default_factory=list)  # read-only checks to run ON the target PC

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "steps": self.steps,
            "verdict_code": self.verdict_code,
            "verdict_title": self.verdict_title,
            "likely_cause": self.likely_cause,
            "confidence": self.confidence,
            "fix_steps": self.fix_steps,
            "target_checks": self.target_checks,
        }


def _step(name: str, status: str, detail: str) -> dict:
    return {"name": name, "status": status, "detail": detail}


def ping_host(ip: str, timeout_s: int = 1) -> tuple[bool, str]:
    """One ICMP ping via the OS ping binary. Args are a fixed list, no shell,
    and `ip` has already been validated as an IPv4 literal."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 3)
    except (OSError, subprocess.TimeoutExpired):
        return False, "Ping could not run on this PC."
    if proc.returncode == 0:
        return True, f"{ip} replied to ping."
    return False, f"No ping reply from {ip} (it may just block ping)."


def tcp_check(ip: str, port: int, timeout: float = PROBE_TIMEOUT) -> TcpResult:
    start = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        ms = int((time.monotonic() - start) * 1000)
        return TcpResult(port, "open", f"Port {port} accepted a connection in {ms} ms.", ms)
    except ConnectionRefusedError:
        ms = int((time.monotonic() - start) * 1000)
        return TcpResult(port, "refused", f"Port {port} actively refused: the PC answered, but nothing is listening there.", ms)
    except (socket.timeout, TimeoutError):
        return TcpResult(port, "filtered", f"Port {port} gave no answer at all (dropped silently).")
    except OSError as exc:
        # e.g. host/network unreachable surfaces immediately on some platforms
        if exc.errno in (113, 101, 111):  # EHOSTUNREACH / ENETUNREACH / ECONNREFUSED variants
            return TcpResult(port, "refused", f"Port {port}: {exc.strerror or exc}.")
        return TcpResult(port, "error", f"Port {port} check errored: {exc.strerror or exc}.")
    finally:
        sock.close()


# Read-only PowerShell checks the user can paste on the TARGET PC.
TARGET_CHECKS = [
    {
        "title": "Is Remote Desktop turned on, and is the service running?",
        "command": "Get-Service TermService; (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections",
        "read": "TermService should be Running. fDenyTSConnections should be 0 (0 = RDP allowed, 1 = RDP blocked).",
    },
    {
        "title": "Is anything listening on the RDP port?",
        "command": "Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue  # replace 3389 if you use a custom RDP port",
        "read": "One or more rows = RDP is listening. No rows = enable Remote Desktop in Settings > System > Remote Desktop.",
    },
    {
        "title": "Is the Windows Firewall allowing Remote Desktop?",
        "command": "Get-NetFirewallRule -DisplayGroup 'Remote Desktop' | Select-Object DisplayName, Enabled, Direction, Action",
        "read": "The inbound rules should be Enabled = True and Action = Allow for your network profile (Private/Public).",
    },
    {
        "title": "Which Windows edition is this PC? (Home cannot accept RDP connections)",
        "command": "(Get-CimInstance Win32_OperatingSystem).Caption; ipconfig",
        "read": "Windows Home can only connect OUT to other PCs; it cannot be connected TO. You need Pro, Enterprise, or Education on the target. ipconfig shows the IPv4 address to connect to.",
    },
]


def build_verdict(d: Diagnosis, *, ping_ok: bool, rdp: TcpResult,
                  hints: list[TcpResult], scenario: str, symptom: str,
                  local_ip: str | None, port: int = RDP_PORT) -> None:
    """Pure decision tree: fills verdict fields from check results."""
    hint_open = [h.port for h in hints if h.state == "open"]
    hint_answered = [h for h in hints if h.state in ("open", "refused")]
    host_alive = ping_ok or bool(hint_answered)
    ip_class = classify_ip(d.resolved_ip or "")
    d.target_checks = TARGET_CHECKS

    if rdp.state == "open":
        d.verdict_code = "rdp_ready"
        d.confidence = "high"
        if symptom in ("login_rejected",):
            d.verdict_title = "RDP port is open: this looks like a sign-in problem, not a network block"
            d.likely_cause = ("The target PC is listening for Remote Desktop, so the network, firewall, and "
                              "router are letting you through. The block is at sign-in: wrong username/password, "
                              "the account isn't allowed Remote Desktop access, or Network Level Authentication (NLA) mismatch.")
            d.fix_steps = [
                "Sign in with an account that exists ON the target PC (try TARGET-PC-NAME\\username), not just your email.",
                "On the target PC: Settings > System > Remote Desktop > Remote Desktop users, and add your account (administrators are allowed automatically).",
                "If the account has no password, set one: Windows blocks remote sign-in for passwordless accounts.",
                "If you see an NLA error, update the PC you're connecting FROM, or on the target turn off 'Require devices to use Network Level Authentication' (less secure, last resort).",
            ]
        elif symptom in ("black_screen",):
            d.verdict_title = "RDP port is open: connection reaches the PC, the session itself is failing"
            d.likely_cause = ("The network path is fine, the Remote Desktop session is breaking after connect: "
                              "usually a stuck session, display driver issue, or a half-broken previous login on the target.")
            d.fix_steps = [
                "Restart the target PC once; stuck RDP sessions clear on reboot.",
                "Connect with a smaller window / lower resolution once (Remote Desktop app > Show options > Display) to rule out a display driver fault.",
                "On the target, sign in locally once to clear any pending update or first-sign-in setup, then retry.",
            ]
        else:
            d.verdict_title = "RDP port is open: the target is ready for Remote Desktop"
            d.likely_cause = (f"Port {port} answered, so Remote Desktop is enabled and no firewall or router is "
                              "blocking it. If the app still fails, the problem is past the network: credentials, "
                              "user permission, or the app itself.")
            d.fix_steps = [
                "Connect using the target's IP address first (rules out name-resolution quirks in the app).",
                "Use an account that exists on the target PC and is allowed Remote Desktop access.",
                "Make sure the connecting account has a password; Windows blocks passwordless remote sign-in.",
            ]
        return

    if rdp.state == "refused":
        d.verdict_code = "rdp_not_listening"
        d.verdict_title = "The PC answered, but RDP isn't listening: Remote Desktop is off or the service is stopped"
        d.likely_cause = (f"The target PC is on the network and responding, but it actively refused port {port}. "
                          "That means nothing is listening for Remote Desktop: RDP is disabled, the Remote Desktop "
                          "Services service is stopped, RDP was moved to a different port, or the PC is a Windows "
                          "Home edition (Home cannot accept RDP connections at all). A firewall almost never "
                          "causes 'refused': firewalls drop silently instead.")
        d.confidence = "high" if host_alive else "medium"
        d.fix_steps = [
            "On the target PC: Settings > System > Remote Desktop, turn Remote Desktop ON. (No such setting = Windows Home, which can't accept RDP.)",
            "On the target PC: open Services, set 'Remote Desktop Services' to Automatic and start it.",
            "If RDP uses a custom port, enter that port in this tool and run the check again.",
            "Run the read-only checks below on the target PC to confirm which of these it is.",
        ]
        return

    # rdp.state == "filtered" (timeout) or "error": the interesting split.
    if hint_open or hint_answered:
        d.verdict_code = "firewall_blocking_rdp"
        d.verdict_title = "Firewall is most likely blocking just the RDP port"
        answered = ", ".join(str(h.port) for h in hint_answered)
        d.likely_cause = (f"The target PC is alive (it answered on port(s) {answered}) but port {port} stayed "
                          "silent. One port dropped while the PC itself responds = a firewall rule is eating RDP "
                          "specifically: Windows Firewall on the target, third-party antivirus/firewall, or a "
                          "router rule between you and it.")
        d.confidence = "high"
        d.fix_steps = [
            "On the target PC: Windows Security > Firewall & network protection > Allow an app through firewall, make sure 'Remote Desktop' is ticked for your network type (Private).",
            f"Check for third-party antivirus/firewall on the target (they often override Windows Firewall) and allow port {port} TCP+UDP there.",
            "If the two PCs are on different networks (guest Wi-Fi, different VLANs), the router may block PC-to-PC traffic: see the network step below.",
            "Run the firewall check below on the target PC to see the actual rule state.",
        ]
        return

    if ping_ok:
        d.verdict_code = "firewall_blocking_all"
        d.verdict_title = "PC is up, but every checked port is silent: host firewall is dropping everything"
        d.likely_cause = (f"The PC replies to ping, so it's on and reachable, but {port} and the Windows ports "
                          "(135/139/445) all timed out. The target's own firewall (Windows Firewall set to Public "
                          "with everything blocked, or a third-party suite) is the prime suspect.")
        d.confidence = "medium"
        d.fix_steps = [
            "On the target PC, check the network profile: Settings > Network > your connection. If it's 'Public', Windows blocks nearly everything inbound; switch trusted home/office networks to Private.",
            "Allow 'Remote Desktop' through the firewall (previous verdict's step 1 covers this).",
            "Temporarily disable any third-party firewall on the target for one test; if RDP then works, fix its rules instead of leaving it off.",
        ]
        return

    # Nothing answered at all.
    if ip_class == "internet":
        d.verdict_code = "remote_access_blocked"
        d.verdict_title = "No answer over the internet path: port forwarding, CGNAT, or the PC is off"
        d.likely_cause = ("Nothing replied at all. For an over-the-internet connection that usually means the "
                          f"router at the target's location isn't forwarding port {port} to the PC, the public IP has "
                          "changed, the internet provider uses CGNAT (no port forwarding possible), or the PC is "
                          "asleep/off. Note: exposing RDP directly to the internet is risky; a VPN (or Remote Desktop "
                          "Gateway) is the safer setup.")
        d.confidence = "medium"
        d.fix_steps = [
            "At the target's location, confirm the PC is on, awake, and note its local IP (ipconfig).",
            f"In that router: forward TCP+UDP {port} to that local IP, and give the PC a reserved/static local IP so it doesn't drift.",
            "Compare the router's WAN IP with a 'what is my IP' site. If they differ, or the WAN IP is in 100.64-100.127 range, you're behind CGNAT: port forwarding won't work. Use a VPN into that network instead.",
            "Simpler and safer alternative: put both PCs on the same VPN (e.g. your router's built-in VPN or a mesh VPN) and connect to the PC's VPN/LAN IP.",
        ]
        if d.resolved_ip and is_cgnat_ip(d.resolved_ip):
            d.likely_cause += " The address you entered is itself a CGNAT address, which strongly suggests CGNAT."
        return

    d.verdict_code = "host_unreachable"
    d.verdict_title = "No answer from the PC at all: it's off, asleep, on another network, or the router is isolating it"
    d.likely_cause = ("No ping reply and no port answered. The PC may be off/asleep/hibernating, connected to a "
                      "different network (guest Wi-Fi, another VLAN, 5 GHz vs 2.4 GHz with client isolation on), "
                      "or the IP may simply be wrong. A router with 'client/AP isolation' on, blocks PCs from "
                      "reaching each other even on the same Wi-Fi.")
    d.confidence = "medium"
    d.fix_steps = [
        "Confirm the target PC is on and awake; set sleep/hibernation to Never while testing (you can't RDP into a sleeping PC).",
        "On the target PC run ipconfig and confirm the IP you're testing is its current one (IPs change; consider a reserved IP in the router).",
        "Make sure both PCs are on the same network name (not guest Wi-Fi) and, in the router, turn OFF 'AP isolation / client isolation' for that network.",
        "If one PC is on VPN, disconnect it for a test: VPNs commonly block local-network access.",
        "Try the Scan button above: if the PC doesn't appear there either, it's a network-join problem, not an RDP problem.",
    ]


def run_diagnosis(target_raw: str, port: int = RDP_PORT, scenario: str = "lan",
                  symptom: str = "generic", local_ip: str | None = None,
                  ping_fn=ping_host, tcp_fn=tcp_check,
                  resolve_fn=resolve_target) -> Diagnosis:
    """Full check sequence against one target. Network functions are
    injectable so tests never touch a real network."""
    d = Diagnosis(target=target_raw)
    resolved, err = resolve_fn(target_raw)
    if err:
        d.steps.append(_step("Name / IP check", "fail", err))
        d.verdict_code = "dns_failure"
        d.verdict_title = "That PC name couldn't be found"
        d.likely_cause = ("The name didn't resolve to an IP address. It may be misspelled, the PC may be off, "
                          "or your network isn't handing out names. Using the IP address directly skips this step.")
        d.confidence = "high"
        d.fix_steps = [
            "On the target PC run ipconfig and use its IPv4 address in this tool.",
            "Check the PC name spelling: Settings > System > About on the target shows its name.",
            "If the IP works but the name doesn't, it's a local DNS/mDNS issue, not an RDP issue.",
        ]
        d.target_checks = TARGET_CHECKS
        return d
    d.resolved_ip = resolved
    is_ip_input = target_raw.strip() == resolved
    d.steps.append(_step("Name / IP check", "pass",
                         f"{'IP address' if is_ip_input else f"'{target_raw}' resolved to"} {resolved}."))

    if local_ip is None:
        from .network_utils import local_ipv4
        local_ip = local_ipv4()

    ip_class = classify_ip(resolved)
    if scenario == "internet" and ip_class in ("lan", "local"):
        d.steps.append(_step("Network path", "warn",
                             "You picked 'Over the internet' but that is a private local-network address, "
                             "which can't be reached from the internet directly. If the PC is in another location, "
                             "enter its public IP or (better) connect to that network by VPN first, then use its local IP."))
    elif scenario == "lan" and ip_class == "internet":
        d.steps.append(_step("Network path", "warn",
                             "You picked 'same network' but that IP is a public internet address. "
                             "If the PC is actually in another location, pick 'Over the internet' and re-run for the right advice."))
    elif ip_class == "internet":
        d.steps.append(_step("Network path", "info",
                             "Target is a public internet IP: the router at that location must forward the RDP port to the PC."))
    elif local_ip and same_subnet(local_ip, resolved) is True:
        d.steps.append(_step("Network path", "info",
                             f"Both PCs appear to be on the same local network (this PC: {local_ip}). Router is unlikely to be the blocker."))
    elif local_ip and ip_class == "lan":
        d.steps.append(_step("Network path", "warn",
                             f"This PC is {local_ip} but the target {resolved} is on a different local subnet. "
                             "Traffic crosses a router/VPN: check routing, VLAN rules, and that the VPN allows local traffic."))
    else:
        d.steps.append(_step("Network path", "info", "Could not fully determine the network path."))

    ping_ok, ping_detail = ping_fn(resolved)
    d.steps.append(_step("Ping test", "pass" if ping_ok else "warn", ping_detail))

    rdp = tcp_fn(resolved, port)
    status = {"open": "pass", "refused": "fail", "filtered": "fail", "error": "warn"}[rdp.state]
    d.steps.append(_step(f"RDP port {port}", status, rdp.detail))

    hints = [tcp_fn(resolved, p) for p in WINDOWS_HINT_PORTS] if port == RDP_PORT else []
    for h in hints:
        if h.state == "open":
            d.steps.append(_step(f"Windows port {h.port}", "pass", f"Port {h.port} is open (typical Windows service)."))
        elif h.state == "refused":
            d.steps.append(_step(f"Windows port {h.port}", "info", f"Port {h.port} refused: host is answering, that service is just off."))
        else:
            d.steps.append(_step(f"Windows port {h.port}", "info", f"Port {h.port} gave no answer."))

    build_verdict(d, ping_ok=ping_ok, rdp=rdp, hints=hints,
                  scenario=scenario, symptom=symptom, local_ip=local_ip, port=port)
    return d

"""Verdict engine tests: fake ping/TCP results, no real network touched."""
from rdp_troubleshooter.diagnostics import TcpResult, run_diagnosis

LOCAL = "192.168.1.2"
TARGET = "192.168.1.42"


def fake(ping_ok, states):
    """states: {port: state}. Returns (ping_fn, tcp_fn)."""
    def ping_fn(ip, timeout_s=1):
        return ping_ok, "fake ping"
    def tcp_fn(ip, port, timeout=2.0):
        return TcpResult(port, states.get(port, "filtered"))
    return ping_fn, tcp_fn


def diagnose(ping_ok, states, **kw):
    ping_fn, tcp_fn = fake(ping_ok, states)
    return run_diagnosis(TARGET, local_ip=LOCAL, ping_fn=ping_fn, tcp_fn=tcp_fn, **kw)


def test_rdp_open_is_ready():
    d = diagnose(True, {3389: "open", 445: "open"})
    assert d.verdict_code == "rdp_ready"


def test_rdp_open_with_login_symptom_points_at_auth():
    d = diagnose(True, {3389: "open"}, symptom="login_rejected")
    assert d.verdict_code == "rdp_ready"
    assert "sign-in" in d.verdict_title.lower()


def test_refused_means_rdp_not_listening_not_firewall():
    d = diagnose(True, {3389: "refused", 445: "open"})
    assert d.verdict_code == "rdp_not_listening"
    assert "firewall" in d.likely_cause.lower()  # explains why it is NOT the firewall


def test_filtered_rdp_but_windows_ports_open_means_firewall():
    d = diagnose(True, {3389: "filtered", 445: "open", 135: "refused"})
    assert d.verdict_code == "firewall_blocking_rdp"


def test_ping_ok_all_ports_filtered_means_host_firewall():
    d = diagnose(True, {3389: "filtered", 445: "filtered", 135: "filtered", 139: "filtered"})
    assert d.verdict_code == "firewall_blocking_all"


def test_nothing_answers_on_lan_means_unreachable():
    d = diagnose(False, {3389: "filtered", 445: "filtered", 135: "filtered", 139: "filtered"})
    assert d.verdict_code == "host_unreachable"


def test_nothing_answers_over_internet_means_port_forward_path():
    # A private target stays on the LAN path even if 'internet' was picked by mistake.
    d = diagnose(False, {3389: "filtered", 445: "filtered", 135: "filtered", 139: "filtered"},
                 scenario="internet")
    assert d.verdict_code == "host_unreachable"
    assert any(s["status"] == "warn" for s in d.steps)
    # A public target takes the remote path.
    ping_fn, tcp_fn = fake(False, {3389: "filtered", 445: "filtered", 135: "filtered", 139: "filtered"})
    d2 = run_diagnosis("8.8.8.8", local_ip=LOCAL, scenario="internet",
                       ping_fn=ping_fn, tcp_fn=tcp_fn)
    assert d2.verdict_code == "remote_access_blocked"


def test_bad_name_is_dns_failure():
    ping_fn, tcp_fn = fake(False, {})
    d = run_diagnosis("no-such-hostname.invalid", local_ip=LOCAL,
                      ping_fn=ping_fn, tcp_fn=tcp_fn,
                      resolve_fn=lambda t: (None, "Could not resolve 'x'."))
    assert d.verdict_code == "dns_failure"


def test_every_verdict_has_fixes_and_target_checks():
    cases = [
        (True, {3389: "open"}),
        (True, {3389: "refused"}),
        (True, {3389: "filtered", 445: "open"}),
        (False, {3389: "filtered"}),
    ]
    for ping_ok, states in cases:
        d = diagnose(ping_ok, states)
        assert d.fix_steps, d.verdict_code
        assert d.target_checks, d.verdict_code
        assert d.verdict_title and d.likely_cause


def test_custom_port_wording():
    ping_fn, tcp_fn = fake(True, {3390: "refused"})
    d = run_diagnosis(TARGET, port=3390, local_ip=LOCAL, ping_fn=ping_fn, tcp_fn=tcp_fn)
    assert d.verdict_code == "rdp_not_listening"
    assert "3390" in d.likely_cause
    assert "port 3389" not in d.likely_cause

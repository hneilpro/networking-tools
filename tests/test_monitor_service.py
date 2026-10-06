"""MonitorService: range filtering, timed sessions, scoped exports."""
import time

import pytest

from network_monitor.monitor import MonitorService, Target
from network_monitor.prober import ProbeResult


def _service():
    svc = MonitorService(probe_fn=lambda host, port: ProbeResult(True, 11.0, "ping"),
                         interval_s=0.05)
    svc._targets = [
        Target("Gateway / router", "192.168.1.1", 80, "gateway"),
        Target("Cloudflare DNS (1.1.1.1)", "1.1.1.1", 443, "internet"),
    ]
    return svc


def _target(svc, host):
    return next(t for t in svc._targets if t.host == host)


def test_status_range_filters_by_time():
    svc = _service()
    now = time.time()
    target = _target(svc, "1.1.1.1")
    target.samples.append((now - 1000, 20.0))
    target.samples.append((now - 5, 10.0))
    near = next(t for t in svc.status(range_s=60)["targets"] if t["host"] == "1.1.1.1")
    assert near["stats"]["samples"] == 1
    assert near["stats"]["median_ms"] == 10.0
    everything = next(t for t in svc.status(range_s="all")["targets"] if t["host"] == "1.1.1.1")
    assert everything["stats"]["samples"] == 2


def test_session_scope_and_outside_fault_conclusion():
    svc = _service()
    svc.start_session(300)
    now = time.time()
    svc._session["started_at"] = now - 100  # session began 100s ago
    gateway = _target(svc, "192.168.1.1")
    internet = _target(svc, "1.1.1.1")
    # Old samples, before the session: terrible, must not count.
    internet.samples.append((now - 1000, 900.0))
    for i in range(6):
        gateway.samples.append((now - 10 + i, 5.0))
    for i in range(10):
        internet.samples.append((now - 10 + i, 10.0 if i % 2 == 0 else 80.0))
    snapshot = svc.cancel_session()
    assert snapshot["state"] == "cancelled"
    report = snapshot["report"]
    net = next(t for t in report["targets"] if t["host"] == "1.1.1.1")
    assert net["stats"]["samples"] == 10  # the pre-session spike is excluded
    assert net["verdict"] in ("unstable", "degraded")
    assert "Outside your home" in report["conclusion"]
    assert "Network Stability Session Report" in snapshot["report_text"]
    assert "1.1.1.1" in snapshot["report_text"]


def test_session_completes_after_duration():
    svc = _service()
    svc.start_session(60)
    svc._session["started_at"] = time.time() - 120
    session = svc.status()["session"]
    assert session["state"] == "complete"
    assert session["progress_pct"] == 100.0


def test_session_double_start_rejected():
    svc = _service()
    svc.start_session(60)
    with pytest.raises(RuntimeError):
        svc.start_session(60)
    with pytest.raises(ValueError):
        svc.start_session(0)
    svc.cancel_session()
    with pytest.raises(RuntimeError):
        svc.cancel_session()


def test_export_csv_session_only():
    svc = _service()
    svc.start_session(300)
    now = time.time()
    svc._session["started_at"] = now - 500  # session began 500s ago
    target = _target(svc, "1.1.1.1")
    target.samples.append((now - 1000, 20.0))
    target.samples.append((now - 5, 10.0))
    session_rows = [ln for ln in svc.export_csv(session_only=True).splitlines()
                    if ",1.1.1.1," in ln]
    all_rows = [ln for ln in svc.export_csv().splitlines() if ",1.1.1.1," in ln]
    assert len(session_rows) == 1
    assert len(all_rows) == 2

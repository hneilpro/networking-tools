"""HTTP layer for the monitor + hub: real servers, injected fake probes."""
import http.client
import json
import threading
from http.server import ThreadingHTTPServer

import pytest

from network_monitor import app as monitor_app
from network_monitor.monitor import MonitorService
from network_monitor.prober import ProbeResult
from networking_hub import app as hub_app


def _call(srv, method, path, token=None, body=None, host="127.0.0.1"):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
    headers = {}
    if token:
        headers["X-Tool-Token"] = token
    if host:
        headers["Host"] = host
    payload = json.dumps(body) if body is not None else None
    if payload:
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=payload, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    headers_out = dict(resp.getheaders())
    conn.close()
    return resp.status, data, headers_out


@pytest.fixture()
def monitor_server():
    service = MonitorService(probe_fn=lambda host, port: ProbeResult(True, 11.0, "ping"),
                             interval_s=0.05)
    token = "test-token"
    srv = ThreadingHTTPServer(("127.0.0.1", 0), monitor_app.make_handler(token, service))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    service.start()
    yield srv, token, service
    service.stop()
    srv.shutdown()
    srv.server_close()


def test_monitor_page_requires_token(monitor_server):
    srv, token, _ = monitor_server
    status, _, _ = _call(srv, "GET", "/")
    assert status == 403
    status, body, _ = _call(srv, "GET", f"/?token={token}", token=None)
    assert status == 200
    assert b"Network Stability Monitor" in body


def test_monitor_status_has_targets(monitor_server):
    srv, token, _ = monitor_server
    status, body, _ = _call(srv, "GET", "/api/status", token=token)
    assert status == 200
    data = json.loads(body)
    assert data["running"] is True
    assert any(t["host"] == "1.1.1.1" for t in data["targets"])


def test_monitor_add_target_and_reject_bad(monitor_server):
    srv, token, _ = monitor_server
    status, _, _ = _call(srv, "POST", "/api/target", token=token,
                         body={"url": "ftp://example.com"})
    assert status == 400
    status, body, _ = _call(srv, "POST", "/api/target", token=token,
                            body={"url": "https://example.com"})
    assert status == 200
    assert json.loads(body)["target"]["host"] == "example.com"


def test_monitor_export_csv(monitor_server):
    srv, token, _ = monitor_server
    status, body, headers = _call(srv, "GET", "/api/export.csv", token=token)
    assert status == 200
    assert "text/csv" in headers["Content-Type"]
    assert body.startswith(b"target,host,timestamp_iso,latency_ms,ok")


def test_monitor_foreign_host_rejected(monitor_server):
    srv, token, _ = monitor_server
    status, _, _ = _call(srv, "GET", "/api/status", token=token, host="evil.example")
    assert status == 403


@pytest.fixture()
def hub_server():
    started = {}

    def fake_builder(name):
        def build():
            srv = ThreadingHTTPServer(("127.0.0.1", 0), hub_app.make_handler("x", hub_app.ToolLauncher({})))
            url = f"http://127.0.0.1:{srv.server_address[1]}/?token=fake-{name}"
            started[name] = srv
            return srv, f"fake-{name}", url
        return build

    launcher = hub_app.ToolLauncher({
        "rdp": ("RDP", fake_builder("rdp")),
        "monitor": ("Monitor", fake_builder("monitor")),
    })
    token = "hub-token"
    srv = ThreadingHTTPServer(("127.0.0.1", 0), hub_app.make_handler(token, launcher))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv, token, launcher
    srv.shutdown()
    srv.server_close()
    for s in started.values():
        s.shutdown()
        s.server_close()


def test_hub_homepage_and_lazy_launch(hub_server):
    srv, token, launcher = hub_server
    status, _, _ = _call(srv, "GET", "/")
    assert status == 403
    status, body, _ = _call(srv, "GET", f"/?token={token}", token=None)
    assert status == 200
    assert b"Remote Desktop Troubleshooter" in body
    assert b"Network Stability Monitor" in body
    assert launcher.started() == {}  # nothing starts until picked
    status, _, headers = _call(srv, "GET", f"/launch/rdp?token={token}", token=None)
    assert status == 302
    assert "token=fake-rdp" in headers["Location"]
    assert "rdp" in launcher.started()
    # Second pick reuses the same server, does not restart it.
    status, _, headers2 = _call(srv, "GET", f"/launch/rdp?token={token}", token=None)
    assert status == 302 and headers2["Location"] == headers["Location"]


def test_hub_unknown_tool_404(hub_server):
    srv, token, _ = hub_server
    status, _, _ = _call(srv, "GET", f"/launch/nope?token={token}", token=None)
    assert status == 404


def test_monitor_status_range_param(monitor_server):
    srv, token, _ = monitor_server
    status, body, _ = _call(srv, "GET", "/api/status?range=60", token=token)
    assert status == 200
    assert json.loads(body)["range_s"] == 60
    status, body, _ = _call(srv, "GET", "/api/status?range=session", token=token)
    assert status == 200  # no session yet: falls back instead of erroring


def test_monitor_session_flow(monitor_server):
    srv, token, _ = monitor_server
    status, body, _ = _call(srv, "POST", "/api/session/start", token=token,
                            body={"duration_min": 1})
    assert status == 200
    assert json.loads(body)["session"]["state"] == "running"
    status, _, _ = _call(srv, "POST", "/api/session/start", token=token,
                         body={"duration_min": 1})
    assert status == 409  # already running
    status, body, headers = _call(srv, "GET", "/api/report.txt", token=token)
    assert status == 200
    assert b"Network Stability Session Report" in body
    status, body, _ = _call(srv, "GET", "/api/export.csv?session=1", token=token)
    assert status == 200
    assert body.startswith(b"target,host,timestamp_iso,latency_ms,ok")
    status, body, _ = _call(srv, "POST", "/api/session/cancel", token=token, body={})
    assert status == 200
    assert json.loads(body)["session"]["state"] == "cancelled"


def test_monitor_expected_speeds_roundtrip(monitor_server, monkeypatch, tmp_path):
    from network_monitor import local_settings
    monkeypatch.setattr(local_settings, "LOCAL_DATA_DIR", tmp_path)
    srv, token, _ = monitor_server
    status, body, _ = _call(srv, "GET", "/api/expected-speeds", token=token)
    assert status == 200
    assert json.loads(body)["expected"] == {"download_mbps": None, "upload_mbps": None}
    status, body, _ = _call(srv, "POST", "/api/expected-speeds", token=token,
                            body={"download_mbps": 500, "upload_mbps": 50})
    assert status == 200
    assert json.loads(body)["expected"] == {"download_mbps": 500.0, "upload_mbps": 50.0}
    status, body, _ = _call(srv, "GET", "/api/expected-speeds", token=token)
    assert json.loads(body)["expected"]["download_mbps"] == 500.0
    # Bad values are a 400, and the saved good values survive it.
    status, _, _ = _call(srv, "POST", "/api/expected-speeds", token=token,
                         body={"download_mbps": -1})
    assert status == 400
    status, body, _ = _call(srv, "GET", "/api/expected-speeds", token=token)
    assert json.loads(body)["expected"]["download_mbps"] == 500.0


def test_monitor_session_bad_duration(monitor_server):
    srv, token, _ = monitor_server
    for bad in ({"duration_min": 0}, {"duration_min": 999}, {}, {"duration_min": "soon"}):
        status, _, _ = _call(srv, "POST", "/api/session/start", token=token, body=bad)
        assert status == 400, bad


def test_monitor_speedtest_incomplete_result_is_not_graded(monitor_server, monkeypatch):
    # A phase that ended early (the v3 failure: 9.41s of 25s, graded
    # "way below expected") must come back labelled incomplete with no
    # plan verdict, even though it carries provisional numbers.
    from network_monitor import local_settings
    monkeypatch.setattr(local_settings, "load_expected_speeds",
                        lambda: {"download_mbps": 300.0, "upload_mbps": 100.0})

    def fake_speed_test(**kwargs):
        return {"ok": True, "download_mbps": 140.0, "upload_mbps": 21.0,
                "download_reliable": False, "upload_reliable": False,
                "reliable": False, "complete": False,
                "error": "Test incomplete: download phase ended early."}

    monkeypatch.setattr(monitor_app, "run_speed_test", fake_speed_test)
    srv, token, _ = monitor_server
    status, body, _ = _call(srv, "POST", "/api/speedtest", token=token, body={})
    assert status == 200
    result = json.loads(body)["result"]
    assert result["overall_assessment"] is None
    for key in ("download_assessment", "upload_assessment"):
        assert result[key]["label"] == "Test incomplete"
        assert result[key]["pct_of_expected"] is None
        assert result[key]["verdict"] == "unknown"
    # The provisional numbers are still shown, just never graded.
    assert result["download_assessment"]["actual_mbps"] == 140.0


def test_monitor_speedtest_reliable_result_is_graded(monitor_server, monkeypatch):
    from network_monitor import local_settings
    monkeypatch.setattr(local_settings, "load_expected_speeds",
                        lambda: {"download_mbps": 300.0, "upload_mbps": 100.0})

    def fake_speed_test(**kwargs):
        return {"ok": True, "download_mbps": 290.0, "upload_mbps": 95.0,
                "download_reliable": True, "upload_reliable": True,
                "reliable": True, "complete": True}

    monkeypatch.setattr(monitor_app, "run_speed_test", fake_speed_test)
    srv, token, _ = monitor_server
    status, body, _ = _call(srv, "POST", "/api/speedtest", token=token, body={})
    assert status == 200
    result = json.loads(body)["result"]
    assert result["download_assessment"]["verdict"] == "excellent"
    assert result["overall_assessment"]["verdict"] == "excellent"

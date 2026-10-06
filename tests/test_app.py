"""HTTP layer tests: real server on a random localhost port, fake diagnosis."""
import http.client
import json
import threading

import pytest
from http.server import ThreadingHTTPServer

from rdp_troubleshooter import app as app_module


@pytest.fixture()
def server():
    token = "test-token"
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app_module.make_handler(token))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv, token
    srv.shutdown()
    srv.server_close()


def call(server, method, path, token=None, body=None, host="127.0.0.1"):
    srv, _ = server
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
    conn.close()
    return resp.status, data


def test_page_requires_token(server):
    _, token = server
    status, _ = call(server, "GET", "/")
    assert status == 403
    status, body = call(server, "GET", f"/?token={token}", token=None)
    assert status == 200
    assert b"Remote Desktop Connection Troubleshooter" in body


def test_api_requires_token(server):
    status, _ = call(server, "GET", "/api/local-info")
    assert status == 403


def test_local_info(server):
    _, token = server
    status, body = call(server, "GET", "/api/local-info", token=token)
    assert status == 200
    assert "local_ip" in json.loads(body)


def test_diagnose_rejects_bad_target(server):
    _, token = server
    status, body = call(server, "POST", "/api/diagnose", token=token,
                        body={"target": "bad host!"})
    assert status == 400
    assert "error" in json.loads(body)


def test_diagnose_localhost_runs(server):
    _, token = server
    status, body = call(server, "POST", "/api/diagnose", token=token,
                        body={"target": "127.0.0.1", "port": 3389})
    assert status == 200
    result = json.loads(body)["result"]
    assert result["resolved_ip"] == "127.0.0.1"
    assert result["verdict_code"]  # some verdict is always produced


def test_scan_rejects_public_network(server):
    _, token = server
    status, body = call(server, "POST", "/api/scan", token=token,
                        body={"cidr": "8.8.8.0/24"})
    assert status == 400


def test_foreign_host_header_rejected(server):
    _, token = server
    status, _ = call(server, "GET", "/api/local-info", token=token, host="evil.example")
    assert status == 403

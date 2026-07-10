"""Web-server mode: serves the HTML dashboard and the JSON report over HTTP."""

import json
import threading
import urllib.error
import urllib.request

from conftest import PCAPS

from argus.server import make_server


def _get(url):
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.status, resp.read().decode("utf-8")


def test_server_serves_dashboard_and_json():
    # port 0 → ephemeral; real fixture so no generated pcaps needed.
    httpd = make_server(str(PCAPS / "zerologon.pcap"), port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        _, port = httpd.server_address
        base = f"http://127.0.0.1:{port}"

        status, html = _get(f"{base}/")
        assert status == 200
        assert html.lstrip().lower().startswith("<!doctype html>")
        assert "CRITICAL" in html and "zerologon" in html

        status, body = _get(f"{base}/report.json")
        assert status == 200
        data = json.loads(body)
        assert data["findings"][0]["rule_id"] == "zerologon"

        # unknown path → 404
        try:
            _get(f"{base}/nope")
            raise AssertionError("expected 404")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_server_binds_localhost_only_by_default():
    httpd = make_server(str(PCAPS / "http.cap"), port=0)
    try:
        host, _ = httpd.server_address
        assert host == "127.0.0.1"  # never 0.0.0.0 — findings are sensitive
    finally:
        httpd.server_close()

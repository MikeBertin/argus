"""Live-updating dashboard: DashboardSink buffer + the threaded HTTP endpoints."""

import json
import threading
import urllib.request

from argus.live import DashboardSink
from argus.models import Finding, Severity
from argus.server import make_dashboard_server


def _get(url):
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.status, resp.read().decode("utf-8")


def test_dashboard_sink_snapshot_counts_and_order():
    sink = DashboardSink("interface en0")
    sink.emit(Finding("port_scan", "vscan", Severity.HIGH, 0.9, src="a", dst="b"), 0.0)
    sink.emit(Finding("zerologon", "zl", Severity.CRITICAL, 0.99), 1.0)
    snap = sink.snapshot()
    assert snap["source"] == "interface en0"
    assert snap["total"] == 2
    assert snap["counts"]["CRITICAL"] == 1 and snap["counts"]["HIGH"] == 1
    assert snap["findings"][0]["rule_id"] == "zerologon"  # newest first


def test_dashboard_server_serves_page_and_live_json():
    sink = DashboardSink("interface en0")
    httpd = make_dashboard_server(sink, "interface en0", port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        _, port = httpd.server_address
        base = f"http://127.0.0.1:{port}"

        status, html = _get(f"{base}/")
        assert status == 200
        assert html.lstrip().lower().startswith("<!doctype html>")
        assert "ARGUS" in html and "/live.json" in html  # the polling page

        _, body = _get(f"{base}/live.json")
        assert json.loads(body)["total"] == 0  # nothing yet

        sink.emit(Finding("arp_spoof", "spoof", Severity.HIGH, 0.9, src="1.1.1.1"), 0.0)
        _, body2 = _get(f"{base}/live.json")
        data = json.loads(body2)
        assert data["total"] == 1
        assert data["findings"][0]["rule_id"] == "arp_spoof"
    finally:
        httpd.shutdown()
        httpd.server_close()

"""Live output sinks: syslog, webhook, multi-fanout, and live severity filtering."""

import http.server
import json
import logging
import threading

from conftest import PCAPS

from argus.ingest import read_pcap
from argus.live import MultiSink, SyslogSink, WebhookSink, monitor
from argus.loader import discover_rules
from argus.models import Finding, Severity


class _CaptureSink:
    def __init__(self):
        self.findings = []

    def emit(self, finding, now):
        self.findings.append(finding)

    def close(self):
        pass


class _CaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


def _finding(rule="port_scan", sev=Severity.HIGH):
    return Finding(rule, "Vertical port scan: 17 ports probed on 10.0.0.1", sev, 0.9,
                   mitre=["T1046"], src="10.0.0.9", dst="10.0.0.1")


def test_syslog_sink_maps_severity_and_formats():
    sink = SyslogSink(handler=_CaptureHandler())
    sink.emit(_finding(sev=Severity.HIGH), now=0.0)
    sink.emit(_finding(rule="beaconing", sev=Severity.MEDIUM), now=0.0)
    records = sink._handler.records
    assert records[0].levelno == logging.ERROR       # HIGH → error
    assert records[1].levelno == logging.WARNING     # MEDIUM → warning
    assert "port_scan" in records[0].getMessage()
    sink.close()


def test_multisink_fans_out():
    a, b = _CaptureSink(), _CaptureSink()
    MultiSink([a, b]).emit(_finding(), now=0.0)
    assert len(a.findings) == 1 and len(b.findings) == 1


def test_webhook_sink_posts_json():
    bodies: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            bodies.append(self.rfile.read(n).decode())
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        _, port = httpd.server_address
        WebhookSink(f"http://127.0.0.1:{port}/hook").emit(_finding(), now=0.0)
        assert bodies, "webhook received no POST"
        payload = json.loads(bodies[0])
        assert payload["rule_id"] == "port_scan"
        assert payload["text"].startswith("[HIGH] port_scan")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_webhook_failure_does_not_raise():
    # nothing listening on this port → emit must swallow the error, not crash.
    WebhookSink("http://127.0.0.1:9/none", timeout=0.2).emit(_finding(), now=0.0)


def test_live_min_severity_filters_enrichment():
    pkts = list(read_pcap(str(PCAPS / "generated/tls_fingerprint.pcap")))
    sink = _CaptureSink()
    monitor(discover_rules(), pkts, sink, tick=0.1, default_window=120.0,
            min_severity=Severity.MEDIUM)
    sevs = {f.severity for f in sink.findings}
    assert Severity.INFO not in sevs                 # enrichment suppressed
    assert any(f.severity >= Severity.HIGH for f in sink.findings)  # hits kept

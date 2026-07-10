"""Web-server mode: serve the ARGUS report over HTTP instead of writing a file.

This is the intended payoff of the report seam — ``build_report_model`` (data) and
``render_html`` (view) are reused unchanged. Uses only the standard library
(``http.server``): no new dependency, and the rendered HTML is already
self-contained. Binds to localhost by default because findings are sensitive.

Routes:
  GET /              -> the interactive HTML dashboard
  GET /report.json   -> the report model as JSON
"""

from __future__ import annotations

import http.server
import json

from argus.engine import Engine
from argus.htmlreport import build_report_model, render_html


def analyze_to_report(pcap_path: str) -> tuple[dict, str]:
    result = Engine().analyze(pcap_path)
    model = build_report_model(result, pcap_path)
    return model, render_html(model)


def build_handler(model: dict, html: str) -> type[http.server.BaseHTTPRequestHandler]:
    html_bytes = html.encode("utf-8")
    json_bytes = json.dumps(model).encode("utf-8")

    class Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, code: int, ctype: str, body: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8", html_bytes)
            elif path in ("/report.json", "/api/report.json"):
                self._send(200, "application/json", json_bytes)
            else:
                self._send(404, "text/plain; charset=utf-8", b"not found")

        do_HEAD = do_GET  # noqa: N815

        def log_message(self, *args) -> None:  # quiet by default
            pass

    return Handler


def make_server(
    pcap_path: str, host: str = "127.0.0.1", port: int = 8000
) -> http.server.HTTPServer:
    """Analyse the pcap once and return a ready (not-yet-serving) HTTP server."""
    model, html = analyze_to_report(pcap_path)
    return http.server.HTTPServer((host, port), build_handler(model, html))


def build_dashboard_handler(sink, html: str) -> type[http.server.BaseHTTPRequestHandler]:
    """Serve the live dashboard page and a live JSON snapshot from ``sink``."""
    html_bytes = html.encode("utf-8")

    class Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, code: int, ctype: str, body: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8", html_bytes)
            elif path == "/live.json":
                body = json.dumps(sink.snapshot()).encode("utf-8")
                self._send(200, "application/json", body)
            else:
                self._send(404, "text/plain; charset=utf-8", b"not found")

        do_HEAD = do_GET  # noqa: N815

        def log_message(self, *args) -> None:
            pass

    return Handler


def make_dashboard_server(
    sink, source: str, host: str = "127.0.0.1", port: int = 8000
) -> http.server.ThreadingHTTPServer:
    """A threaded HTTP server for the live dashboard, reading from ``sink``."""
    from argus.htmlreport import render_live_dashboard

    html = render_live_dashboard(source)
    return http.server.ThreadingHTTPServer(
        (host, port), build_dashboard_handler(sink, html)
    )


def serve(pcap_path: str, host: str = "127.0.0.1", port: int = 8000) -> None:
    httpd = make_server(pcap_path, host, port)
    bound_host, bound_port = httpd.server_address
    print(f"ARGUS report for {pcap_path}")
    print(f"  → http://{bound_host}:{bound_port}/            (dashboard)")
    print(
        f"  → http://{bound_host}:{bound_port}/report.json (JSON)   ·  Ctrl-C to stop",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()

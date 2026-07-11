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


# --------------------------------------------------------------------------- #
# Browser-upload web app
# --------------------------------------------------------------------------- #
MAX_UPLOAD_BYTES = 64 * 1024 * 1024  # 64 MB cap


def _parse_upload(headers, body: bytes):
    """Extract (filename, bytes) from a multipart/form-data body. Uses the email
    parser (cgi.FieldStorage was removed in Python 3.13)."""
    import email

    ctype = headers.get("Content-Type", "")
    if "multipart/form-data" not in ctype:
        return None, None
    raw = b"Content-Type: " + ctype.encode() + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    msg = email.message_from_bytes(raw)
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            return filename, part.get_payload(decode=True)
    return None, None


def analyze_upload(filename: str, data: bytes) -> tuple[int, str]:
    """Write uploaded bytes to a temp pcap, analyse, return (status, HTML).

    Runs on the caller's thread — must be the main thread, because pyshark spawns
    tshark via asyncio, whose subprocess support is main-thread-only (hence the
    upload server is single-threaded).
    """
    import os
    import tempfile

    from argus.htmlreport import build_report_model, render_error_page, render_html

    suffix = os.path.splitext(filename)[1] or ".pcap"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tf:
        tf.write(data)
        path = tf.name
    try:
        result = Engine().analyze(path)
        return 200, render_html(build_report_model(result, filename))
    except Exception as exc:  # not a valid capture, tshark error, ...
        return 400, render_error_page(f"Could not analyse {filename}", str(exc))
    finally:
        os.unlink(path)


def build_upload_handler() -> type[http.server.BaseHTTPRequestHandler]:
    from argus.htmlreport import render_error_page, render_upload_page

    upload_page = render_upload_page().encode("utf-8")

    class Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, code: int, ctype: str, body: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _html(self, code: int, html: str) -> None:
            self._send(code, "text/html; charset=utf-8", html.encode("utf-8"))

        def do_GET(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8", upload_page)
            else:
                self._send(404, "text/plain; charset=utf-8", b"not found")

        do_HEAD = do_GET  # noqa: N815

        def do_POST(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] != "/analyze":
                self._send(404, "text/plain; charset=utf-8", b"not found")
                return
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_UPLOAD_BYTES:
                self._html(413, render_error_page(
                    "Upload too large",
                    f"Capture exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit."))
                return
            filename, data = _parse_upload(self.headers, self.rfile.read(length))
            if not data:
                self._html(400, render_error_page(
                    "No capture received", "The form did not include a pcap file."))
                return
            code, html = analyze_upload(filename, data)
            self._html(code, html)

        def log_message(self, *args) -> None:
            pass

    return Handler


def make_upload_server(
    host: str = "127.0.0.1", port: int = 8000
) -> http.server.HTTPServer:
    # Single-threaded on purpose: analysis (pyshark→tshark via asyncio) must run on
    # the main serve_forever thread — asyncio subprocesses are main-thread-only.
    return http.server.HTTPServer((host, port), build_upload_handler())


def serve_upload(host: str = "127.0.0.1", port: int = 8000) -> None:
    httpd = make_upload_server(host, port)
    bound_host, bound_port = httpd.server_address
    print(
        f"ARGUS upload app → http://{bound_host}:{bound_port}/   (drop a pcap · Ctrl-C to stop)",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()


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

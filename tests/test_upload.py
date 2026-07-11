"""Browser-upload web app: multipart parse, analyse → report / error, upload page.

The analyse path is tested via ``analyze_upload`` directly (main thread) because
pyshark spawns tshark through asyncio, whose subprocess support is main-thread-only
— which is also why the upload server is single-threaded.
"""

import threading
import urllib.request

from conftest import PCAPS

from argus.server import _parse_upload, analyze_upload, make_upload_server

BOUNDARY = "----argus-test-boundary"


def _multipart(filename: str, data: bytes) -> bytes:
    return (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="pcap"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + data + f"\r\n--{BOUNDARY}--\r\n".encode()


def test_parse_upload_extracts_file():
    body = _multipart("x.pcap", b"HELLOBYTES")
    fn, data = _parse_upload(
        {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}, body
    )
    assert fn == "x.pcap" and data == b"HELLOBYTES"


def test_analyze_upload_returns_report():
    with open(PCAPS / "zerologon.pcap", "rb") as fh:
        code, html = analyze_upload("zerologon.pcap", fh.read())
    assert code == 200
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert "CRITICAL" in html and "zerologon" in html


def test_analyze_upload_rejects_garbage_gracefully():
    code, html = analyze_upload("junk.pcap", b"not a pcap at all")
    assert code == 400
    assert "could not analyse" in html.lower()


def test_upload_page_served():
    httpd = make_upload_server(port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        _, port = httpd.server_address
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10) as r:
            page = r.read().decode()
        assert "Drop a .pcap" in page and "/analyze" in page
    finally:
        httpd.shutdown()
        httpd.server_close()

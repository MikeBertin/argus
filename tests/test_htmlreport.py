"""HTML report: model correctness, render content, and self-containment."""

import re

from conftest import PCAPS

from argus.engine import AnalysisResult
from argus.htmlreport import build_report_model, render_html
from argus.models import Finding, Severity


def _sample_result() -> AnalysisResult:
    return AnalysisResult(
        findings=[
            Finding("zerologon", "Zerologon brute-force", Severity.CRITICAL, 0.99,
                    mitre=["T1210"], src="10.0.0.9", dst="10.0.0.6",
                    evidence={"target_dc": "DC01"}, packets=[32], ts=1700000000.0),
            Finding("beaconing", "Beaconing to C2", Severity.MEDIUM, 0.7,
                    mitre=["T1071"], evidence={}, packets=[1], ts=1700000300.0),
        ],
        packet_count=1000,
        flow_count=42,
        rules_run=5,
        start_ts=1700000000.0,
        end_ts=1700000300.0,
    )


def test_model_counts_and_attack():
    model = build_report_model(_sample_result(), "sample.pcap")
    assert model["severity_counts"]["CRITICAL"] == 1
    assert model["severity_counts"]["MEDIUM"] == 1
    assert model["packets"] == 1000 and model["flows"] == 42
    ids = {a["id"] for a in model["attack"]}
    assert ids == {"T1210", "T1071"}
    # attack list sorted with most-severe technique first
    assert model["attack"][0]["id"] == "T1210"


def test_render_contains_expected_content():
    model = build_report_model(_sample_result(), "sample.pcap")
    html = render_html(model)
    assert html.lstrip().lower().startswith("<!doctype html>")
    for marker in ("ARGUS", "CRITICAL", "T1210", "Zerologon", "DC01", "argus-data"):
        assert marker in html


def test_render_is_self_contained():
    """No external asset loads. Only attack.mitre.org anchor hrefs may be http(s)."""
    model = build_report_model(_sample_result(), "sample.pcap")
    html = render_html(model)
    external = re.findall(r'(?:src|href)\s*=\s*"(https?://[^"]+)"', html)
    offenders = [u for u in external if "attack.mitre.org" not in u]
    assert offenders == [], f"external asset references found: {offenders}"
    # no CDN-style protocol-relative or script src either
    assert 'src="//' not in html
    assert "<script src" not in html


def test_render_clean_capture_has_no_findings_banner():
    empty = AnalysisResult(findings=[], packet_count=10, flow_count=2, rules_run=5)
    html = render_html(build_report_model(empty, "clean.pcap"))
    assert "No findings" in html


def test_end_to_end_zerologon_report():
    from argus.engine import Engine

    result = Engine().analyze(str(PCAPS / "zerologon.pcap"))
    html = render_html(build_report_model(result, "zerologon.pcap"))
    assert "CRITICAL" in html and "T1210" in html and "DC01" in html

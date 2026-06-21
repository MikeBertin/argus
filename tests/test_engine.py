"""Engine / loader / model smoke tests (no pcap parsing needed)."""

import json

from argus.context import AnalysisContext
from argus.engine import Engine
from argus.loader import discover_rules
from argus.models import Finding, NormalizedPacket, Rule, Severity


def test_loader_discovers_all_rules():
    rules = discover_rules()
    ids = {r.id for r in rules}
    assert {
        "zerologon", "dns_tunnel", "icmp_exfil", "cleartext_creds",
        "beaconing", "port_scan", "arp_spoof", "bruteforce", "ja3_fingerprint",
    } <= ids
    # ids are unique
    assert len(ids) == len(rules)
    # every rule is a concrete Rule
    assert all(isinstance(r, Rule) for r in rules)


def test_flow_assembly_is_bidirectional():
    ctx = AnalysisContext()
    a = NormalizedPacket(1, 0.0, "1.1.1.1", "2.2.2.2", 1000, 80, "TCP", 60)
    b = NormalizedPacket(2, 0.1, "2.2.2.2", "1.1.1.1", 80, 1000, "TCP", 60)
    ctx.observe(a)
    ctx.observe(b)
    assert len(ctx.flows) == 1  # both directions collapse to one flow


def test_findings_sorted_by_severity_desc():
    class HiRule(Rule):
        id = "hi"

        def finalize(self, ctx):
            return [Finding("hi", "h", Severity.CRITICAL, 0.5)]

    class LoRule(Rule):
        id = "lo"

        def finalize(self, ctx):
            return [Finding("lo", "l", Severity.LOW, 0.9)]

    # empty pcap path not needed: drive finalize via a tiny fake capture
    eng = Engine(rules=[LoRule(), HiRule()])
    # monkeypatch ingest to yield nothing
    import argus.engine as engine_mod

    orig = engine_mod.read_pcap
    engine_mod.read_pcap = lambda _p: iter(())
    try:
        result = eng.analyze("unused")
    finally:
        engine_mod.read_pcap = orig

    sevs = [f.severity for f in result.findings]
    assert sevs == sorted(sevs, reverse=True)
    assert sevs[0] is Severity.CRITICAL


def test_finding_to_dict_is_json_serialisable():
    f = Finding("r", "t", Severity.HIGH, 0.8, mitre=["T1"], evidence={"a": 1})
    blob = json.dumps(f.to_dict())
    assert json.loads(blob)["severity"] == "HIGH"

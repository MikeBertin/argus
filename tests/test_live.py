"""Live monitoring: replay fixtures through ``monitor`` with a synthetic clock.

No interface or root needed — packets are re-timestamped and fed as a list, so
windowing/eviction/dedup are exercised deterministically.
"""

from conftest import PCAPS

from argus.ingest import read_pcap
from argus.live import Deduper, monitor
from argus.loader import discover_rules
from argus.models import Finding, Severity


class CaptureSink:
    def __init__(self):
        self.findings: list[Finding] = []

    def emit(self, finding, now):
        self.findings.append(finding)

    def close(self):
        pass


def _restamp(packets, base, step=0.02):
    for i, pkt in enumerate(packets):
        pkt.ts = base + i * step
    return packets


def _run(packets, tick=0.1, window=120.0):
    sink = CaptureSink()
    monitor(discover_rules(), packets, sink, tick=tick, default_window=window)
    return sink.findings


def test_aggregating_rule_fires_live():
    pkts = _restamp(list(read_pcap(str(PCAPS / "generated/port_scan_vertical.pcap"))), 0.0)
    fired = {f.rule_id for f in _run(pkts)}
    assert "port_scan" in fired


def test_immediate_rule_fires_live():
    pkts = list(read_pcap(str(PCAPS / "generated/cleartext_login.pcap")))
    fired = {f.rule_id for f in _run(pkts)}
    assert "cleartext_creds" in fired


def test_dedup_suppresses_repeats_within_cooldown():
    # Threshold is crossed early, then many more ticks occur — the same finding
    # must be emitted only once.
    pkts = _restamp(list(read_pcap(str(PCAPS / "generated/port_scan_vertical.pcap"))), 0.0)
    scans = [f for f in _run(pkts) if f.rule_id == "port_scan"]
    assert len(scans) == 1


def test_eviction_re_arms_threshold():
    # Batch 1, then batch 2 well past the window: eviction clears batch 1's state
    # and the dedup cooldown expires, so the scan fires a second time.
    base = list(read_pcap(str(PCAPS / "generated/port_scan_vertical.pcap")))
    batch1 = _restamp(list(base), 0.0)
    batch2 = _restamp(list(read_pcap(str(PCAPS / "generated/port_scan_vertical.pcap"))), 500.0)
    scans = [f for f in _run(batch1 + batch2, window=120.0) if f.rule_id == "port_scan"]
    assert len(scans) == 2


def test_deduper_cooldown():
    d = Deduper(cooldown=10.0)
    f = Finding("r", "title", Severity.HIGH, 0.9, src="a", dst="b")
    assert d.is_new(f, now=0.0) is True
    assert d.is_new(f, now=5.0) is False       # within cooldown
    assert d.is_new(f, now=11.0) is True        # cooldown expired

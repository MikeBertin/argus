"""The engine: drives ingest → flow assembly → rules → ranked findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from argus.context import AnalysisContext
from argus.ingest import read_pcap
from argus.loader import discover_rules
from argus.models import Finding, Rule


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    packet_count: int = 0
    flow_count: int = 0
    rules_run: int = 0
    start_ts: float | None = None
    end_ts: float | None = None


class Engine:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules if rules is not None else discover_rules()

    def analyze(self, pcap_path: str) -> AnalysisResult:
        ctx = AnalysisContext()
        findings: list[Finding] = []

        for pkt in read_pcap(pcap_path):
            ctx.observe(pkt)
            for rule in self.rules:
                findings.extend(rule.inspect_packet(pkt, ctx))

        for rule in self.rules:
            findings.extend(rule.finalize(ctx))

        # Resolve a timestamp for each finding from its first referenced packet.
        for f in findings:
            if f.ts is None and f.packets:
                f.ts = ctx.packet_times.get(f.packets[0])

        findings.sort(key=lambda f: (f.severity, f.confidence), reverse=True)
        return AnalysisResult(
            findings=findings,
            packet_count=ctx.packet_count,
            flow_count=len(ctx.flows),
            rules_run=len(self.rules),
            start_ts=ctx.first_ts,
            end_ts=ctx.last_ts,
        )

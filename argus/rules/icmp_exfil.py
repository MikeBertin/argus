"""ICMP exfiltration / covert-channel detection.

Standard pings carry a small fixed payload (~48–56 bytes). Data smuggled over
ICMP rides in oversized echo payloads, so a run of large-payload echo packets to
one destination is the signal. Normal 48-byte pings stay well under threshold.
"""

from __future__ import annotations

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, layer

ICMP_ECHO_REQUEST = "8"


class IcmpExfilRule(Rule):
    id = "icmp_exfil"
    name = "ICMP exfiltration / covert channel"
    severity = Severity.HIGH
    mitre = ["T1048.003"]
    confidence = 0.8
    description = "Repeated oversized ICMP echo payloads to one destination."

    OVERSIZE_BYTES = 256
    MIN_PACKETS = 3

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        icmp = layer(pkt, "icmp")
        if icmp is None:
            return []
        if field(icmp, "type") != ICMP_ECHO_REQUEST:
            return []
        try:
            data_len = int(field(icmp, "data_len", default=0))
        except (TypeError, ValueError):
            return []
        if data_len <= self.OVERSIZE_BYTES:
            return []

        ctx.window(self.id).add((pkt.src, pkt.dst), pkt.ts, (data_len, pkt.number))
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for (src, dst), obs in ctx.window(self.id).items():
            if len(obs) < self.MIN_PACKETS:
                continue
            sizes = [o[0] for o in obs]
            frames = [o[1] for o in obs]
            findings.append(
                self.finding(
                    title=(
                        f"ICMP exfiltration: {len(sizes)} oversized echo packets "
                        f"(max {max(sizes)} B payload)"
                    ),
                    confidence=self.confidence,
                    src=src,
                    dst=dst,
                    evidence={
                        "oversized_packets": len(sizes),
                        "total_payload_bytes": sum(sizes),
                        "max_payload_bytes": max(sizes),
                        "threshold_bytes": self.OVERSIZE_BYTES,
                    },
                    packets=frames[:20],
                )
            )
        return findings

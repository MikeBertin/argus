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

        rec = ctx.scratch(self.id).setdefault(
            (pkt.src, pkt.dst),
            {"count": 0, "total_bytes": 0, "max": 0, "frames": []},
        )
        rec["count"] += 1
        rec["total_bytes"] += data_len
        rec["max"] = max(rec["max"], data_len)
        rec["frames"].append(pkt.number)
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for (src, dst), rec in ctx.scratch(self.id).items():
            if rec["count"] < self.MIN_PACKETS:
                continue
            findings.append(
                self.finding(
                    title=(
                        f"ICMP exfiltration: {rec['count']} oversized echo packets "
                        f"(max {rec['max']} B payload)"
                    ),
                    confidence=self.confidence,
                    src=src,
                    dst=dst,
                    evidence={
                        "oversized_packets": rec["count"],
                        "total_payload_bytes": rec["total_bytes"],
                        "max_payload_bytes": rec["max"],
                        "threshold_bytes": self.OVERSIZE_BYTES,
                    },
                    packets=rec["frames"][:20],
                )
            )
        return findings

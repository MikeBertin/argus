"""C2 beaconing detection.

Implants call home on a fixed cadence, producing many connections to one
destination at a near-constant interval (low jitter). Detection groups TCP
connections by (src, dst, dport) — ignoring the ephemeral source port — and
flags low coefficient-of-variation inter-arrival times over a minimum count.
Bursty, irregular human traffic has high jitter and is not flagged.
"""

from __future__ import annotations

import statistics

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity


class BeaconingRule(Rule):
    id = "beaconing"
    name = "Periodic C2 beaconing"
    severity = Severity.MEDIUM
    mitre = ["T1071"]
    confidence = 0.6
    description = "Many connections to one destination at a regular, low-jitter interval."

    MIN_BEACONS = 6
    MIN_INTERVAL = 1.0     # seconds — ignore sub-second chatter
    MAX_CV = 0.15          # coefficient of variation (stdev/mean) of intervals

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        # Only TCP connection attempts (SYNs already counted as packets here).
        if not pkt.proto.startswith("TCP") or pkt.dport is None:
            return []
        rec = ctx.scratch(self.id).setdefault(
            (pkt.src, pkt.dst, pkt.dport),
            {"times": [], "first_frame": pkt.number},
        )
        rec["times"].append(pkt.ts)
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for (src, dst, dport), rec in ctx.scratch(self.id).items():
            times = rec["times"]
            if len(times) < self.MIN_BEACONS:
                continue
            times = sorted(times)
            intervals = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
            if len(intervals) < self.MIN_BEACONS - 1:
                continue
            mean = statistics.mean(intervals)
            if mean < self.MIN_INTERVAL:
                continue
            stdev = statistics.pstdev(intervals)
            cv = stdev / mean if mean else 1.0
            if cv > self.MAX_CV:
                continue
            findings.append(
                self.finding(
                    title=(
                        f"Beaconing: {len(times)} connections to {dst}:{dport} "
                        f"every ~{mean:.1f}s (jitter {cv * 100:.0f}%)"
                    ),
                    confidence=min(0.9, 0.6 + (self.MAX_CV - cv)),
                    src=src,
                    dst=dst,
                    evidence={
                        "dest_port": dport,
                        "connections": len(times),
                        "mean_interval_s": round(mean, 2),
                        "jitter_cv": round(cv, 3),
                    },
                    packets=[rec["first_frame"]],
                )
            )
        return findings

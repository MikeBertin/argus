"""5-tuple flow assembly — the backbone behavioural rules build on.

A flow is a bidirectional conversation, canonicalised so both directions map to
the same key. Per-direction counts are retained so rules can tell client from
server. Timestamps are kept for inter-arrival analysis (beaconing).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from argus.models import NormalizedPacket

FlowKey = tuple[str, str, str, int, int]


def canonical_key(pkt: NormalizedPacket) -> FlowKey:
    """Direction-independent key: (proto, ip_lo, ip_hi, port_lo, port_hi)."""
    a = (pkt.src or "", pkt.sport or 0)
    b = (pkt.dst or "", pkt.dport or 0)
    lo, hi = sorted((a, b))
    return (pkt.proto, lo[0], hi[0], lo[1], hi[1])


@dataclass
class Flow:
    key: FlowKey
    proto: str
    first_ts: float
    last_ts: float
    packets: int = 0
    bytes: int = 0
    # per-direction packet counts keyed by (src, dst)
    directions: dict[tuple[str | None, str | None], int] = field(default_factory=dict)
    timestamps: list[float] = field(default_factory=list)

    def update(self, pkt: NormalizedPacket) -> None:
        self.packets += 1
        self.bytes += pkt.length
        self.last_ts = pkt.ts
        self.timestamps.append(pkt.ts)
        d = (pkt.src, pkt.dst)
        self.directions[d] = self.directions.get(d, 0) + 1

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)


class FlowTable:
    """Holds all flows for a capture; updated once per packet."""

    def __init__(self) -> None:
        self._flows: dict[FlowKey, Flow] = {}

    def observe(self, pkt: NormalizedPacket) -> Flow:
        key = canonical_key(pkt)
        flow = self._flows.get(key)
        if flow is None:
            flow = Flow(key=key, proto=pkt.proto, first_ts=pkt.ts, last_ts=pkt.ts)
            self._flows[key] = flow
        flow.update(pkt)
        return flow

    def evict(self, cutoff: float) -> None:
        """Drop flows with no activity since ``cutoff`` (live-mode memory hygiene)."""
        for key in list(self._flows):
            if self._flows[key].last_ts < cutoff:
                del self._flows[key]

    def __len__(self) -> int:
        return len(self._flows)

    def values(self):
        return self._flows.values()

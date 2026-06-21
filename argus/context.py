"""Shared analysis state passed to every rule.

``flows`` is the assembled flow table; ``scratch`` gives each rule an isolated
namespace to accumulate state across ``inspect_packet`` calls without colliding
with other rules.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from argus.flows import FlowTable
from argus.models import NormalizedPacket


class AnalysisContext:
    def __init__(self) -> None:
        self.flows = FlowTable()
        self.packet_count = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        # frame number -> epoch ts, used to place findings on the timeline.
        # O(packets) memory; fine for capture-file triage.
        self.packet_times: dict[int, float] = {}
        self._scratch: dict[str, dict[Any, Any]] = defaultdict(dict)

    def scratch(self, rule_id: str) -> dict[Any, Any]:
        """Per-rule mutable namespace (created on first access)."""
        return self._scratch[rule_id]

    def observe(self, pkt: NormalizedPacket) -> None:
        self.packet_count += 1
        self.flows.observe(pkt)
        if pkt.ts:
            self.packet_times[pkt.number] = pkt.ts
            if self.first_ts is None or pkt.ts < self.first_ts:
                self.first_ts = pkt.ts
            if self.last_ts is None or pkt.ts > self.last_ts:
                self.last_ts = pkt.ts

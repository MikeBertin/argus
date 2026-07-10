"""Shared analysis state passed to every rule.

``flows`` is the assembled flow table; ``scratch`` gives each rule an isolated
namespace to accumulate state across ``inspect_packet`` calls without colliding
with other rules.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterator

from argus.flows import FlowTable
from argus.models import NormalizedPacket


class WindowStore:
    """Timestamped per-rule observations, keyed by the rule's natural key.

    Each event is ``(ts, payload, frame)``. ``evict(cutoff)`` drops events older
    than ``cutoff`` (and keys that become empty), which is how a live monitor keeps
    thresholds reflecting a sliding time window instead of accumulating forever.
    """

    def __init__(self) -> None:
        self._events: dict[Any, list[tuple[float, Any, int | None]]] = defaultdict(list)

    def add(self, key: Any, ts: float, payload: Any = None, frame: int | None = None) -> None:
        self._events[key].append((ts, payload, frame))

    def evict(self, cutoff: float) -> None:
        for key in list(self._events):
            kept = [e for e in self._events[key] if e[0] >= cutoff]
            if kept:
                self._events[key] = kept
            else:
                del self._events[key]

    def items(self) -> Iterator[tuple[Any, list[Any]]]:
        for key, events in self._events.items():
            yield key, [e[1] for e in events]

    def payloads(self, key: Any) -> list[Any]:
        return [e[1] for e in self._events.get(key, [])]

    def timestamps(self, key: Any) -> list[float]:
        return [e[0] for e in self._events.get(key, [])]

    def first_frame(self, key: Any) -> int | None:
        frames = [e[2] for e in self._events.get(key, []) if e[2] is not None]
        return min(frames) if frames else None

    def __contains__(self, key: Any) -> bool:
        return key in self._events

    def __len__(self) -> int:
        return len(self._events)


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
        self._windows: dict[str, WindowStore] = {}

    def scratch(self, rule_id: str) -> dict[Any, Any]:
        """Per-rule mutable namespace (created on first access)."""
        return self._scratch[rule_id]

    def window(self, rule_id: str) -> WindowStore:
        """Per-rule timestamped observation store (created on first access)."""
        store = self._windows.get(rule_id)
        if store is None:
            store = self._windows[rule_id] = WindowStore()
        return store

    def observe(self, pkt: NormalizedPacket) -> None:
        self.packet_count += 1
        self.flows.observe(pkt)
        if pkt.ts:
            self.packet_times[pkt.number] = pkt.ts
            if self.first_ts is None or pkt.ts < self.first_ts:
                self.first_ts = pkt.ts
            if self.last_ts is None or pkt.ts > self.last_ts:
                self.last_ts = pkt.ts

    def evict(self, rule_windows: dict[str, float], now: float) -> None:
        """Evict per-rule events older than each rule's window, and prune shared
        memory (packet_times, flows) beyond the largest window. Live mode only."""
        for rule_id, store in self._windows.items():
            window = rule_windows.get(rule_id)
            if window is not None:
                store.evict(now - window)
        max_window = max(rule_windows.values(), default=0.0)
        if max_window > 0:
            cutoff = now - max_window
            self.packet_times = {
                f: t for f, t in self.packet_times.items() if t >= cutoff
            }
            self.flows.evict(cutoff)

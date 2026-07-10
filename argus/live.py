"""Live monitoring: turn ARGUS into a continuous IDS.

The batch engine runs every rule's ``finalize`` once at end-of-file. A live stream
never ends, so ``monitor`` instead evaluates on a periodic tick over a *sliding
time window*: rules accumulate timestamped observations in per-rule
:class:`~argus.context.WindowStore`s, the context evicts events older than each
rule's window before every finalize pass, and a :class:`Deduper` suppresses a
finding from re-alerting each tick. The loop is clocked by packet timestamps, so
replaying a pcap through it is fully deterministic (and CI-safe — no interface).
"""

from __future__ import annotations

import json
import re
from typing import Callable, Iterable

from rich.console import Console

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


class Deduper:
    """Suppress repeat findings within a cooldown, keyed by rule/endpoints/title."""

    def __init__(self, cooldown: float) -> None:
        self.cooldown = cooldown
        self._seen: dict[tuple, float] = {}

    def is_new(self, finding: Finding, now: float) -> bool:
        # Normalise digits out of the title so a growing count ("17 ports" →
        # "18 ports") is treated as the same alert, while genuinely different
        # findings (distinct wording) stay distinct.
        title_id = re.sub(r"\d+", "#", finding.title)
        key = (finding.rule_id, finding.src, finding.dst, title_id)
        last = self._seen.get(key)
        if last is None or now - last >= self.cooldown:
            self._seen[key] = now
            return True
        return False


class FindingSink:
    """Emit findings as a human line (stdout) and optionally JSON-lines to a file."""

    def __init__(self, jsonl_path: str | None = None, console: Console | None = None) -> None:
        self.console = console or Console()
        self._jsonl = open(jsonl_path, "a", encoding="utf-8") if jsonl_path else None

    def emit(self, finding: Finding, now: float) -> None:
        style = _SEV_STYLE.get(finding.severity, "")
        endpoints = ""
        if finding.src or finding.dst:
            endpoints = f"  {finding.src or '?'} → {finding.dst or '?'}"
        attack = f"  [{', '.join(finding.mitre)}]" if finding.mitre else ""
        self.console.print(
            f"[{style}] {finding.severity.name:8}[/] {finding.rule_id:16}"
            f"{endpoints}{attack}  {finding.title}"
        )
        if self._jsonl:
            self._jsonl.write(json.dumps(finding.to_dict()) + "\n")
            self._jsonl.flush()

    def close(self) -> None:
        if self._jsonl:
            self._jsonl.close()
            self._jsonl = None


def rule_windows(rules: list[Rule], default_window: float) -> dict[str, float]:
    return {r.id: (r.window_seconds or default_window) for r in rules}


def _resolve_ts(finding: Finding, ctx: AnalysisContext, now: float) -> None:
    if finding.ts is None:
        if finding.packets:
            finding.ts = ctx.packet_times.get(finding.packets[0])
        if finding.ts is None:
            finding.ts = now


def monitor(
    rules: list[Rule],
    source: Iterable[NormalizedPacket],
    sink: FindingSink,
    tick: float = 5.0,
    default_window: float = 120.0,
    deduper: Deduper | None = None,
    on_packet: Callable[[NormalizedPacket], None] | None = None,
) -> None:
    """Consume packets from ``source`` and stream findings to ``sink`` until the
    source is exhausted (or interrupted). Clock = packet timestamp."""
    ctx = AnalysisContext()
    dedup = deduper or Deduper(cooldown=default_window)
    windows = rule_windows(rules, default_window)
    last_tick: float | None = None

    def evaluate(now: float, immediate_pkt: NormalizedPacket | None) -> None:
        for rule in rules:
            emitted = (
                rule.inspect_packet(immediate_pkt, ctx)
                if immediate_pkt is not None
                else rule.finalize(ctx)
            )
            for finding in emitted:
                _resolve_ts(finding, ctx, now)
                if dedup.is_new(finding, now):
                    sink.emit(finding, now)

    for pkt in source:
        if on_packet is not None:
            on_packet(pkt)
        ctx.observe(pkt)
        now = pkt.ts or last_tick or 0.0
        evaluate(now, pkt)  # immediate (per-packet) findings

        if last_tick is None:
            last_tick = now
        if now - last_tick >= tick:
            ctx.evict(windows, now)
            evaluate(now, None)  # windowed finalize pass
            last_tick = now

    # final flush so a threshold reached just before the source ended still fires
    if last_tick is not None:
        ctx.evict(windows, last_tick)
        evaluate(last_tick, None)

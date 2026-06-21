"""Core data types and the Rule plugin contract.

These types are deliberately decoupled from pyshark: a ``NormalizedPacket``
carries the common 5-tuple fields every rule needs, plus ``raw`` for the rare
rule (e.g. zerologon) that must reach into protocol-specific dissector fields.
"""

from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # avoid a circular import at runtime
    from argus.context import AnalysisContext


class Severity(IntEnum):
    """Ordered severity — higher sorts first in the report."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass
class NormalizedPacket:
    """A protocol-agnostic view of one packet.

    ``raw`` is the underlying pyshark packet (or any object) for rules that
    need deep field access; it may be ``None`` for synthetically built packets.
    """

    number: int
    ts: float
    src: str | None
    dst: str | None
    sport: int | None
    dport: int | None
    proto: str
    length: int
    raw: Any = None


@dataclass
class Finding:
    """A single detection result emitted by a rule."""

    rule_id: str
    title: str
    severity: Severity
    confidence: float
    mitre: list[str] = field(default_factory=list)
    src: str | None = None
    dst: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    packets: list[int] = field(default_factory=list)
    # epoch time of the finding (resolved by the engine from its first packet)
    ts: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "confidence": round(self.confidence, 3),
            "mitre": self.mitre,
            "src": self.src,
            "dst": self.dst,
            "evidence": self.evidence,
            "packets": self.packets,
            "ts": self.ts,
        }


class Rule(ABC):
    """Base class for every detection. Subclasses are auto-discovered.

    Two-pass model:
      * ``inspect_packet`` runs once per packet — accumulate state in ``ctx``
        and/or emit immediate findings.
      * ``finalize`` runs after the whole capture is read — emit verdicts that
        depend on aggregated flow state (beaconing, tunnelling volume, ...).

    Stateless rules implement only ``inspect_packet``; purely behavioural rules
    implement only ``finalize``. Both default to a no-op so subclasses override
    just what they need.
    """

    id: str = "base"
    name: str = "Base Rule"
    severity: Severity = Severity.INFO
    mitre: list[str] = []
    confidence: float = 0.8
    description: str = ""

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: "AnalysisContext"
    ) -> list[Finding]:
        return []

    def finalize(self, ctx: "AnalysisContext") -> list[Finding]:
        return []

    # convenience for subclasses --------------------------------------------
    def finding(self, **kwargs: Any) -> Finding:
        """Build a Finding, defaulting rule_id/severity/mitre/confidence."""
        kwargs.setdefault("rule_id", self.id)
        kwargs.setdefault("severity", self.severity)
        kwargs.setdefault("mitre", list(self.mitre))
        kwargs.setdefault("confidence", self.confidence)
        return Finding(**kwargs)

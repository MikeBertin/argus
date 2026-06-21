"""LLMNR / NBT-NS poisoning detection (Responder-style).

LLMNR (UDP 5355) and NBT-NS (UDP 137) are fallback name-resolution protocols.
A legitimate host only ever *answers* for its own name. A poisoner (e.g.
Responder) answers queries for many different names — all resolving to the
attacker — to coerce victims into authenticating to it (NTLM capture/relay).

Signal: a single responder that answers name queries for several distinct names.
"""

from __future__ import annotations

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, layer, truthy


class LlmnrSpoofRule(Rule):
    id = "llmnr_spoof"
    name = "LLMNR/NBT-NS poisoning (Responder)"
    severity = Severity.HIGH
    mitre = ["T1557.001"]
    confidence = 0.85
    description = "One responder answering name queries for several distinct names."

    MIN_NAMES = 3

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        llmnr = layer(pkt, "llmnr")
        nbns = layer(pkt, "nbns")
        if llmnr is not None:
            if not truthy(field(llmnr, "dns_flags_response")):
                return []
            name = field(llmnr, "dns_qry_name")
            proto = "LLMNR"
        elif nbns is not None:
            if not truthy(field(nbns, "flags_response")):
                return []
            name = field(nbns, "name")
            proto = "NBT-NS"
        else:
            return []
        if not name:
            return []

        rec = ctx.scratch(self.id).setdefault(
            pkt.src,
            {"names": set(), "protocols": set(), "count": 0, "first": pkt.number},
        )
        rec["names"].add(str(name).strip())
        rec["protocols"].add(proto)
        rec["count"] += 1
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for responder, rec in ctx.scratch(self.id).items():
            if len(rec["names"]) < self.MIN_NAMES:
                continue
            names = sorted(rec["names"])
            findings.append(
                self.finding(
                    title=(
                        f"LLMNR/NBT-NS poisoning: {responder} answered "
                        f"{len(names)} distinct names"
                    ),
                    confidence=min(0.97, self.confidence + 0.02 * len(names)),
                    src=responder,
                    dst=None,
                    evidence={
                        "responder": responder,
                        "protocols": sorted(rec["protocols"]),
                        "names_answered": names[:15],
                        "distinct_names": len(names),
                        "responses": rec["count"],
                    },
                    packets=[rec["first"]],
                )
            )
        return findings

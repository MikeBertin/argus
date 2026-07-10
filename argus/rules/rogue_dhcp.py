"""Rogue DHCP server detection.

A rogue DHCP server races the legitimate one to hand clients a malicious default
gateway or DNS server, redirecting traffic for a man-in-the-middle. The robust,
false-positive-safe signal is **conflicting configuration offered** — two or more
distinct gateways (or DNS server sets) seen across DHCP OFFER/ACK messages. This
does not trip on redundant servers that agree (e.g. ISP failover pairs offering
the same gateway), which a naive "more than one server" check would.
"""

from __future__ import annotations

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, field_values, layer

DHCP_OFFER = "2"
DHCP_ACK = "5"


class RogueDhcpRule(Rule):
    id = "rogue_dhcp"
    name = "Rogue DHCP server"
    severity = Severity.HIGH
    mitre = ["T1557"]
    confidence = 0.85
    description = "Conflicting gateway/DNS offered by DHCP — a rogue server redirecting traffic."

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        dhcp = layer(pkt, "dhcp")
        if dhcp is None:
            return []
        if field(dhcp, "option_dhcp") not in (DHCP_OFFER, DHCP_ACK):
            return []  # only server→client messages carry the offered config

        ctx.window(self.id).add(
            "offers",
            pkt.ts,
            {
                "gateways": field_values(dhcp, "option_router"),
                "dns": frozenset(field_values(dhcp, "option_domain_name_server")),
                "server_id": field(dhcp, "option_dhcp_server_id"),
                "src": pkt.src,
            },
            frame=pkt.number,
        )
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        store = ctx.window(self.id)
        offers = store.payloads("offers")
        if not offers:
            return []

        gateways: dict[str, str] = {}  # gateway -> server_id that offered it
        dns_sets: set[frozenset] = set()
        servers: set[str] = set()
        first_frame = store.first_frame("offers")
        for o in offers:
            for gw in o["gateways"]:
                gateways.setdefault(gw, o["server_id"] or o["src"])
            if o["dns"]:
                dns_sets.add(o["dns"])
            servers.add(o["server_id"] or o["src"])

        conflict_gw = len(gateways) >= 2
        conflict_dns = len(dns_sets) >= 2
        if not (conflict_gw or conflict_dns):
            return []

        reason = []
        if conflict_gw:
            reason.append(f"{len(gateways)} distinct gateways")
        if conflict_dns:
            reason.append(f"{len(dns_sets)} distinct DNS sets")
        return [
            self.finding(
                title=f"Rogue DHCP: conflicting config offered ({', '.join(reason)})",
                confidence=self.confidence,
                src=None,
                dst=None,
                evidence={
                    "gateways_offered": gateways,
                    "dns_sets_offered": [sorted(s) for s in dns_sets],
                    "dhcp_servers": sorted(servers),
                },
                packets=[first_frame],
            )
        ]

"""ARP cache poisoning (spoofing) detection.

ARP has no authentication, so an attacker can forge replies binding a victim or
gateway IP to the attacker's MAC, redirecting traffic for a man-in-the-middle.
The classic, low-false-positive signal (the arpwatch approach) is a single IP
suddenly claimed by two or more distinct MAC addresses. Normal ARP — even large
volumes of requests/replies — keeps a stable one-IP-to-one-MAC mapping.
"""

from __future__ import annotations

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, layer

ARP_REPLY = "2"


class ArpSpoofRule(Rule):
    id = "arp_spoof"
    name = "ARP cache poisoning (spoofing)"
    severity = Severity.HIGH
    mitre = ["T1557.002"]
    confidence = 0.85
    description = "One IP address claimed by multiple MAC addresses (ARP poisoning)."

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        arp = layer(pkt, "arp")
        if arp is None:
            return []
        ip = field(arp, "src_proto_ipv4")
        mac = field(arp, "src_hw_mac")
        if not ip or not mac:
            return []

        is_reply = str(field(arp, "opcode")) == ARP_REPLY
        ctx.window(self.id).add(ip, pkt.ts, (mac, is_reply, pkt.number), frame=pkt.number)
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        store = ctx.window(self.id)
        for ip, obs in store.items():
            macs: dict[str, int] = {}
            replies = 0
            conflict_frame = None
            for mac, is_reply, frame in obs:
                before = len(macs)
                macs[mac] = macs.get(mac, 0) + 1
                if is_reply:
                    replies += 1
                if before < 2 <= len(macs) and conflict_frame is None:
                    conflict_frame = frame
            if len(macs) < 2:
                continue
            # More forged replies → higher confidence in an active poisoning.
            confidence = min(0.98, self.confidence + 0.02 * replies)
            findings.append(
                self.finding(
                    title=f"ARP spoofing: {ip} claimed by {len(macs)} MAC addresses",
                    confidence=confidence,
                    src=ip,
                    dst=None,
                    evidence={
                        "ip": ip,
                        "mac_addresses": list(macs.keys()),
                        "arp_replies": replies,
                    },
                    packets=[conflict_frame or store.first_frame(ip)],
                )
            )
        return findings

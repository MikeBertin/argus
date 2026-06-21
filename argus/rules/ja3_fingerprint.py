"""TLS client fingerprinting via JA3.

For every TLS Client Hello, ARGUS computes the JA3 fingerprint and:
  * flags it HIGH (T1573, Encrypted Channel) if it matches the known-bad blocklist;
  * otherwise records it as INFO enrichment, so an analyst can pivot on the
    fingerprint (e.g. spot the same client across destinations) even with no hit.
"""

from __future__ import annotations

from argus.context import AnalysisContext
from argus.ja3 import compute_ja3
from argus.ja3_blocklist import load_blocklist
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, layer

CLIENT_HELLO = "1"


class Ja3FingerprintRule(Rule):
    id = "ja3_fingerprint"
    name = "TLS client fingerprint (JA3)"
    severity = Severity.HIGH
    mitre = ["T1573"]
    confidence = 0.85
    description = "JA3 fingerprint of a TLS Client Hello, matched against a blocklist."

    def __init__(self) -> None:
        self.blocklist = load_blocklist()

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        tls = layer(pkt, "tls")
        if tls is None:
            return []
        if str(field(tls, "handshake_type")) != CLIENT_HELLO:
            return []
        result = compute_ja3(tls)
        if result is None:
            return []
        ja3_str, ja3_md5 = result

        rec = ctx.scratch(self.id).setdefault(
            ja3_md5,
            {"ja3": ja3_str, "count": 0, "dsts": set(), "src": None, "first": pkt.number},
        )
        rec["count"] += 1
        if pkt.dst:
            rec["dsts"].add(pkt.dst)
        rec["src"] = pkt.src
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for ja3_md5, rec in ctx.scratch(self.id).items():
            dsts = sorted(rec["dsts"])
            hit = self.blocklist.get(ja3_md5)
            if hit:
                findings.append(
                    self.finding(
                        title=f"Malicious TLS client (JA3): {hit.get('label', 'blocklisted')}",
                        severity=Severity.HIGH,
                        confidence=self.confidence,
                        src=rec["src"],
                        dst=dsts[0] if dsts else None,
                        evidence={
                            "ja3": ja3_md5,
                            "ja3_string": rec["ja3"],
                            "blocklist_label": hit.get("label"),
                            "blocklist_source": hit.get("source"),
                            "client_hellos": rec["count"],
                            "destinations": dsts,
                        },
                        packets=[rec["first"]],
                    )
                )
            else:
                findings.append(
                    self.finding(
                        title=f"TLS client JA3 {ja3_md5} ({rec['count']} hello(s))",
                        severity=Severity.INFO,
                        confidence=1.0,
                        mitre=[],
                        src=rec["src"],
                        dst=dsts[0] if dsts else None,
                        evidence={
                            "ja3": ja3_md5,
                            "ja3_string": rec["ja3"],
                            "client_hellos": rec["count"],
                            "destinations": dsts,
                        },
                        packets=[rec["first"]],
                    )
                )
        return findings

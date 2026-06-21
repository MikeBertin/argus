"""TLS client fingerprinting via JA3 and JA4.

For every TLS Client Hello, ARGUS computes both the JA3 (MD5) and JA4 (FoxIO)
fingerprints and:
  * flags it HIGH (T1573, Encrypted Channel) if *either* matches the known-bad
    blocklist;
  * otherwise records one INFO enrichment finding carrying both fingerprints, so
    an analyst can pivot on the client stack (e.g. spot it across destinations).

JA4 supersedes JA3; surfacing both keeps legacy intel usable while moving forward.
"""

from __future__ import annotations

from argus.context import AnalysisContext
from argus.fingerprint_blocklist import load_blocklist
from argus.ja3 import compute_ja3
from argus.ja4 import compute_ja4
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, layer

CLIENT_HELLO = "1"


class TlsFingerprintRule(Rule):
    id = "tls_fingerprint"
    name = "TLS client fingerprint (JA3/JA4)"
    severity = Severity.HIGH
    mitre = ["T1573"]
    confidence = 0.85
    description = "JA3/JA4 fingerprint of a TLS Client Hello, matched against a blocklist."

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
        ja3 = compute_ja3(tls)
        ja4 = compute_ja4(tls)
        if ja3 is None and ja4 is None:
            return []
        ja3_md5 = ja3[1] if ja3 else None
        ja3_str = ja3[0] if ja3 else None

        # group by the (ja3, ja4) pair — a unique client stack
        rec = ctx.scratch(self.id).setdefault(
            (ja3_md5, ja4),
            {"ja3_str": ja3_str, "count": 0, "dsts": set(), "src": None, "first": pkt.number},
        )
        rec["count"] += 1
        if pkt.dst:
            rec["dsts"].add(pkt.dst)
        rec["src"] = pkt.src
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for (ja3_md5, ja4), rec in ctx.scratch(self.id).items():
            dsts = sorted(rec["dsts"])
            # a hit on either fingerprint is a detection
            hit = self.blocklist.get(ja3_md5) or self.blocklist.get(ja4)
            base_evidence = {
                "ja3": ja3_md5,
                "ja3_string": rec["ja3_str"],
                "ja4": ja4,
                "client_hellos": rec["count"],
                "destinations": dsts,
            }
            if hit:
                findings.append(
                    self.finding(
                        title=f"Malicious TLS client: {hit.get('label', 'blocklisted')}",
                        severity=Severity.HIGH,
                        confidence=self.confidence,
                        src=rec["src"],
                        dst=dsts[0] if dsts else None,
                        evidence={
                            **base_evidence,
                            "blocklist_label": hit.get("label"),
                            "blocklist_source": hit.get("source"),
                        },
                        packets=[rec["first"]],
                    )
                )
            else:
                findings.append(
                    self.finding(
                        title=f"TLS client fingerprint  JA4 {ja4}  JA3 {ja3_md5}",
                        severity=Severity.INFO,
                        confidence=1.0,
                        mitre=[],
                        src=rec["src"],
                        dst=dsts[0] if dsts else None,
                        evidence=base_evidence,
                        packets=[rec["first"]],
                    )
                )
        return findings

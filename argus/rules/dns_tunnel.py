"""DNS tunnelling / exfiltration detection.

Tunnelling encodes data into the leftmost DNS labels, producing a stream of
long, high-entropy subdomains under one parent domain. Normal lookups (incl.
PTR reverse lookups) use short, low-entropy, dictionary-ish labels, so the
combination of *volume + length + entropy* per parent domain separates them.
"""

from __future__ import annotations

import statistics

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, layer, shannon_entropy


def _parent_domain(qname: str) -> str:
    parts = qname.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else qname


def _leftmost_label(qname: str) -> str:
    return qname.rstrip(".").split(".")[0]


class DnsTunnelRule(Rule):
    id = "dns_tunnel"
    name = "DNS tunnelling / exfiltration"
    severity = Severity.HIGH
    mitre = ["T1071.004", "T1048.003"]
    confidence = 0.85
    description = (
        "High volume of long, high-entropy subdomains under one parent domain."
    )

    MIN_QUERIES = 8
    MIN_AVG_LABEL_LEN = 20
    MIN_AVG_ENTROPY = 3.5  # bits/char

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        dns = layer(pkt, "dns")
        if dns is None:
            return []
        # Count requests only (responses echo the same qry_name).
        if str(field(dns, "flags_response", default="0")).lower() in ("1", "true"):
            return []
        qname = field(dns, "qry_name")
        if not qname:
            return []

        label = _leftmost_label(qname)
        ctx.window(self.id).add(
            _parent_domain(qname),
            pkt.ts,
            (label, pkt.src, pkt.dst),
            frame=pkt.number,
        )
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        store = ctx.window(self.id)
        for parent, obs in store.items():
            queries = len(obs)
            if queries < self.MIN_QUERIES:
                continue
            labels = {o[0] for o in obs}
            avg_len = statistics.mean(len(o[0]) for o in obs)
            avg_entropy = statistics.mean(shannon_entropy(o[0]) for o in obs)
            if avg_len < self.MIN_AVG_LABEL_LEN or avg_entropy < self.MIN_AVG_ENTROPY:
                continue
            findings.append(
                self.finding(
                    title=(
                        f"DNS tunnelling: {queries} long high-entropy "
                        f"subdomains under '{parent}'"
                    ),
                    confidence=min(0.99, 0.7 + avg_entropy / 20),
                    src=obs[-1][1],
                    dst=obs[-1][2],
                    evidence={
                        "parent_domain": parent,
                        "queries": queries,
                        "unique_subdomains": len(labels),
                        "avg_label_len": round(avg_len, 1),
                        "avg_label_entropy": round(avg_entropy, 2),
                    },
                    packets=[store.first_frame(parent)],
                )
            )
        return findings

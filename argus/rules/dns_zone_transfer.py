"""DNS zone transfer (AXFR/IXFR) detection.

A zone transfer asks a nameserver to hand over an *entire* DNS zone in one
shot — every host, service and subdomain it knows. It is the intended
replication mechanism between a primary and its authorised secondaries, but to
an attacker it is a free, complete map of the internal network: one ``AXFR`` to
a misconfigured server dumps the whole namespace with no scanning.

Signal: a DNS query of type ``AXFR`` (252) or ``IXFR`` (251). These run over
**TCP/53** (a full zone won't fit a UDP datagram) and are otherwise vanishingly
rare on a normal client — ordinary lookups are A/AAAA/PTR/SRV/etc. Grounding
confirmed the benign captures only ever use those ordinary qtypes, so keying on
the transfer qtype carries essentially no false-positive cost. Normal
*DNS-over-TCP* (large or DNSSEC responses) is **not** flagged: the discriminator
is the qtype, not the transport.

Two tiers, because an attempt and a success are different facts:
  * request seen, or refused              -> MEDIUM (reconnaissance attempt)
  * response carried answer records       -> HIGH   (the zone actually leaked)

Honest caveat: an authorised secondary nameserver replicating from its primary
produces the same signal. The rule cannot know which server pairs are
authorised without site config, so it reports the transfer and names the pair
in the evidence; operators whitelist known primary/secondary IPs downstream.
"""

from __future__ import annotations

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, layer, truthy

# DNS query types that request a bulk zone transfer.
_XFR_TYPES = {"252": "AXFR", "251": "IXFR"}


class DnsZoneTransferRule(Rule):
    id = "dns_zone_transfer"
    name = "DNS zone transfer (AXFR/IXFR)"
    severity = Severity.MEDIUM  # attempt-level; elevated to HIGH on success
    mitre = ["T1590.002"]
    confidence = 0.75
    description = (
        "A DNS AXFR/IXFR zone-transfer request — bulk dump of an entire DNS "
        "zone, i.e. a complete map of the internal namespace."
    )

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        dns = layer(pkt, "dns")
        if dns is None:
            return []
        xfr = _XFR_TYPES.get(str(field(dns, "qry_type", default="")))
        if xfr is None:
            return []

        is_response = truthy(field(dns, "flags_response"))
        zone = str(field(dns, "qry_name", default="?")).rstrip(".") or "?"
        # Normalise so a request and its response fold onto one key: the client
        # is whoever asked, the server is whoever holds the zone, regardless of
        # packet direction.
        client, server = (pkt.dst, pkt.src) if is_response else (pkt.src, pkt.dst)

        answers = 0
        if is_response:
            try:
                answers = int(field(dns, "count_answers", default="0") or 0)
            except (TypeError, ValueError):
                answers = 0

        ctx.window(self.id).add(
            (client, server, zone),
            pkt.ts,
            ("response" if is_response else "request", answers, xfr),
            frame=pkt.number,
        )
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        store = ctx.window(self.id)
        for (client, server, zone), obs in store.items():
            max_answers = max((o[1] for o in obs), default=0)
            succeeded = max_answers > 0
            xfr = next((o[2] for o in obs), "AXFR")

            if succeeded:
                severity, confidence, verb = Severity.HIGH, 0.9, "succeeded"
                tail = f" ({max_answers} records)"
            else:
                severity, confidence, verb = Severity.MEDIUM, 0.75, "attempt"
                tail = ""

            findings.append(
                self.finding(
                    title=(
                        f"DNS zone transfer {verb}: {client} -> {server} "
                        f"for zone '{zone}'{tail}"
                    ),
                    severity=severity,
                    confidence=confidence,
                    src=client,
                    dst=server,
                    evidence={
                        "client": client,
                        "server": server,
                        "zone": zone,
                        "transfer_type": xfr,
                        "succeeded": succeeded,
                        "records_transferred": max_answers,
                    },
                    packets=[store.first_frame((client, server, zone))],
                )
            )
        return findings

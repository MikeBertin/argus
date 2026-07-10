"""TLS fingerprinting via JA3, JA4 (client) and JA4S (server).

For every TLS Client Hello, ARGUS computes JA3 (MD5) + JA4 (FoxIO); for every
Server Hello it computes JA4S. Each is:
  * flagged HIGH (T1573, Encrypted Channel) if it matches the known-bad blocklist;
  * otherwise recorded as INFO enrichment so an analyst can pivot on the client or
    server TLS stack (e.g. identify a C2 server by its JA4S across IPs).
"""

from __future__ import annotations

from argus.context import AnalysisContext
from argus.fingerprint_blocklist import load_blocklist
from argus.ja3 import compute_ja3
from argus.ja4 import compute_ja4, compute_ja4s
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, layer

CLIENT_HELLO = "1"
SERVER_HELLO = "2"


class TlsFingerprintRule(Rule):
    id = "tls_fingerprint"
    name = "TLS fingerprint (JA3/JA4 client, JA4S server)"
    severity = Severity.HIGH
    mitre = ["T1573"]
    confidence = 0.85
    description = "JA3/JA4/JA4S TLS fingerprints matched against a blocklist."

    def __init__(self) -> None:
        self.blocklist = load_blocklist()

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        tls = layer(pkt, "tls")
        if tls is None:
            return []
        htype = str(field(tls, "handshake_type"))
        scratch = ctx.scratch(self.id)

        if htype == CLIENT_HELLO:
            ja3 = compute_ja3(tls)
            ja4 = compute_ja4(tls)
            if ja3 is None and ja4 is None:
                return []
            key = (ja3[1] if ja3 else None, ja4)
            rec = scratch.setdefault("client", {}).setdefault(
                key,
                {"ja3_str": ja3[0] if ja3 else None, "count": 0,
                 "dsts": set(), "src": None, "first": pkt.number},
            )
            rec["count"] += 1
            if pkt.dst:
                rec["dsts"].add(pkt.dst)
            rec["src"] = pkt.src
        elif htype == SERVER_HELLO:
            ja4s = compute_ja4s(tls)
            if ja4s is None:
                return []
            rec = scratch.setdefault("server", {}).setdefault(
                ja4s,
                {"count": 0, "clients": set(), "server": None, "first": pkt.number},
            )
            rec["count"] += 1
            if pkt.dst:
                rec["clients"].add(pkt.dst)
            rec["server"] = pkt.src
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        scratch = ctx.scratch(self.id)
        findings: list[Finding] = []

        # --- client fingerprints (JA3 / JA4) ---
        for (ja3_md5, ja4), rec in scratch.get("client", {}).items():
            dsts = sorted(rec["dsts"])
            hit = self.blocklist.get(ja3_md5) or self.blocklist.get(ja4)
            ev = {"ja3": ja3_md5, "ja3_string": rec["ja3_str"], "ja4": ja4,
                  "client_hellos": rec["count"], "destinations": dsts}
            findings.append(self._finding(hit, ev, rec["src"], dsts[0] if dsts else None,
                                           rec["first"], "client",
                                           f"JA4 {ja4}  JA3 {ja3_md5}"))

        # --- server fingerprints (JA4S) ---
        for ja4s, rec in scratch.get("server", {}).items():
            clients = sorted(rec["clients"])
            hit = self.blocklist.get(ja4s)
            ev = {"ja4s": ja4s, "server_hellos": rec["count"], "clients": clients}
            findings.append(self._finding(hit, ev, rec["server"],
                                           clients[0] if clients else None,
                                           rec["first"], "server", f"JA4S {ja4s}"))
        return findings

    def _finding(self, hit, evidence, src, dst, frame, side, label) -> Finding:
        if hit:
            return self.finding(
                title=f"Malicious TLS {side}: {hit.get('label', 'blocklisted')}",
                severity=Severity.HIGH,
                confidence=self.confidence,
                src=src, dst=dst,
                evidence={**evidence, "blocklist_label": hit.get("label"),
                          "blocklist_source": hit.get("source")},
                packets=[frame],
            )
        return self.finding(
            title=f"TLS {side} fingerprint  {label}",
            severity=Severity.INFO,
            confidence=1.0,
            mitre=[],
            src=src, dst=dst,
            evidence=evidence,
            packets=[frame],
        )

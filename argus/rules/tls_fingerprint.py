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
        store = ctx.window(self.id)

        if htype == CLIENT_HELLO:
            ja3 = compute_ja3(tls)
            ja4 = compute_ja4(tls)
            if ja3 is None and ja4 is None:
                return []
            key = ("client", ja3[1] if ja3 else None, ja4)
            store.add(key, pkt.ts, (ja3[0] if ja3 else None, pkt.dst, pkt.src),
                      frame=pkt.number)
        elif htype == SERVER_HELLO:
            ja4s = compute_ja4s(tls)
            if ja4s is None:
                return []
            store.add(("server", ja4s), pkt.ts, (pkt.dst, pkt.src), frame=pkt.number)
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        store = ctx.window(self.id)
        findings: list[Finding] = []

        for key, obs in store.items():
            first = store.first_frame(key)
            if key[0] == "client":
                _, ja3_md5, ja4 = key
                dsts = sorted({o[1] for o in obs if o[1]})
                hit = self.blocklist.get(ja3_md5) or self.blocklist.get(ja4)
                ev = {"ja3": ja3_md5, "ja3_string": obs[0][0], "ja4": ja4,
                      "client_hellos": len(obs), "destinations": dsts}
                findings.append(self._finding(
                    hit, ev, obs[-1][2], dsts[0] if dsts else None, first,
                    "client", f"JA4 {ja4}  JA3 {ja3_md5}"))
            else:  # server
                _, ja4s = key
                clients = sorted({o[0] for o in obs if o[0]})
                hit = self.blocklist.get(ja4s)
                ev = {"ja4s": ja4s, "server_hellos": len(obs), "clients": clients}
                findings.append(self._finding(
                    hit, ev, obs[-1][1], clients[0] if clients else None, first,
                    "server", f"JA4S {ja4s}"))
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

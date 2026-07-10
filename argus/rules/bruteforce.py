"""Credential brute-force / password-spraying detection.

A brute-force or spraying attack opens many separate connections to a single
authentication service (SMB, RDP, SSH, ...) from one source — one connection per
login attempt. RDP and modern SMB are encrypted, so the robust, protocol-agnostic
signal is the *volume of established connections to one auth-service port*.

Distinguished from neighbours:
  * port scan  — many *different* ports, half-open / no data (here: one port, established).
  * beaconing  — regular low-jitter interval (here: rapid, high volume).
Counting only connections that establish (SYN-ACK) or exchange data avoids
mislabelling a SYN scan/flood as a brute-force.
"""

from __future__ import annotations

from collections import defaultdict

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, layer, truthy

AUTH_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
}


class BruteForceRule(Rule):
    id = "bruteforce"
    name = "Credential brute-force / password spraying"
    severity = Severity.HIGH
    mitre = ["T1110"]
    confidence = 0.75
    description = "Many login connections to a single authentication service."

    MIN_ATTEMPTS = 10

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        tcp = layer(pkt, "tcp")
        if tcp is None or pkt.sport is None or pkt.dport is None:
            return []

        # Orient the packet relative to the auth-service side.
        if pkt.dport in AUTH_PORTS:
            client, server, svc_port, client_port, forward = (
                pkt.src, pkt.dst, pkt.dport, pkt.sport, True,
            )
        elif pkt.sport in AUTH_PORTS:
            client, server, svc_port, client_port, forward = (
                pkt.dst, pkt.src, pkt.sport, pkt.dport, False,
            )
        else:
            return []

        try:
            seg_len = int(field(tcp, "len", default=0))
        except (TypeError, ValueError):
            seg_len = 0

        # SYN-ACK from the server (reverse) → established; forward payload → data;
        # anything else is just a connection "touch". One observation per packet.
        if not forward and truthy(field(tcp, "flags_syn")) and truthy(field(tcp, "flags_ack")):
            kind = "established"
        elif seg_len > 0:
            kind = "data"
        else:
            kind = None
        ctx.window(self.id).add(
            (client, server, svc_port, client_port), pkt.ts, kind, frame=pkt.number
        )
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        store = ctx.window(self.id)
        groups: dict = defaultdict(
            lambda: {"conns": set(), "attempt_conns": set(), "first": None}
        )
        for (client, server, svc_port, client_port), kinds in store.items():
            g = groups[(client, server, svc_port)]
            g["conns"].add(client_port)
            if any(k in ("established", "data") for k in kinds):
                g["attempt_conns"].add(client_port)
            first = store.first_frame((client, server, svc_port, client_port))
            if g["first"] is None or (first is not None and first < g["first"]):
                g["first"] = first

        findings: list[Finding] = []
        for (client, server, svc_port), g in groups.items():
            attempts = len(g["attempt_conns"])
            if attempts < self.MIN_ATTEMPTS:
                continue
            svc = AUTH_PORTS.get(svc_port, str(svc_port))
            findings.append(
                self.finding(
                    title=(
                        f"{svc} brute-force: {attempts} login connections to "
                        f"{server}:{svc_port}"
                    ),
                    confidence=min(0.95, 0.6 + 0.02 * attempts),
                    src=client,
                    dst=server,
                    evidence={
                        "service": svc,
                        "port": svc_port,
                        "login_attempts": attempts,
                        "distinct_connections": len(g["conns"]),
                    },
                    packets=[g["first"]],
                )
            )
        return findings

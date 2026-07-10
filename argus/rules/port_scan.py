"""Port-scan detection (vertical + horizontal).

Two shapes, one backbone:
  * vertical   — one source probing many ports on a single host (service enum).
  * horizontal — one source probing one port across many hosts (subnet sweep).

The discriminator from *legitimate* many-port traffic (e.g. RPC dynamic ports) is
that a scan target is a SYN with **no application data exchanged** — the scanner
never completes a real conversation. Half-open targets (SYN with no SYN-ACK)
push confidence higher, marking a classic stealth/SYN scan.

Note: TCP is detected by the presence of the ``tcp`` layer, not ``proto == TCP``
— packets that dissect to a higher layer (RPC, HTTP) are still TCP and their data
must be seen, otherwise established connections look (wrongly) scan-like.
"""

from __future__ import annotations

from collections import defaultdict

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, layer


def _truth(value) -> bool:
    return value is True or str(value).lower() in ("1", "true")


class PortScanRule(Rule):
    id = "port_scan"
    name = "Port scan (network service discovery)"
    severity = Severity.MEDIUM
    mitre = ["T1046"]
    confidence = 0.6
    description = "One source probing many ports/hosts with unestablished SYNs."

    MIN_TARGETS = 15

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        tcp = layer(pkt, "tcp")
        if tcp is None or pkt.dport is None:
            return []
        syn = _truth(field(tcp, "flags_syn"))
        ack = _truth(field(tcp, "flags_ack"))
        try:
            seg_len = int(field(tcp, "len", default=0))
        except (TypeError, ValueError):
            seg_len = 0

        targets = ctx.window(self.id)

        if syn and not ack:
            # client → server SYN: this names a target.
            targets.add((pkt.src, pkt.dst, pkt.dport), pkt.ts, "syn", frame=pkt.number)
        elif syn and ack:
            # server → client SYN-ACK: response to (client, server, server_port).
            targets.add((pkt.dst, pkt.src, pkt.sport), pkt.ts, "synack", frame=pkt.number)

        if seg_len > 0:
            fwd = (pkt.src, pkt.dst, pkt.dport)
            rev = (pkt.dst, pkt.src, pkt.sport)
            if fwd in targets:
                targets.add(fwd, pkt.ts, "data", frame=pkt.number)
            elif rev in targets:
                targets.add(rev, pkt.ts, "data", frame=pkt.number)
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        targets = ctx.window(self.id)
        # vertical: (client, server) -> scan-like ports ; horizontal: (client, port) -> hosts
        vert: dict = defaultdict(lambda: {"ports": set(), "half_open": 0, "first": None})
        horiz: dict = defaultdict(lambda: {"hosts": set(), "half_open": 0, "first": None})

        for (client, server, port), kinds in targets.items():
            if "syn" not in kinds or "data" in kinds:
                continue  # never SYN'd, or a real conversation → not a scan target
            half_open = "synack" not in kinds
            first = targets.first_frame((client, server, port))

            v = vert[(client, server)]
            v["ports"].add(port)
            v["half_open"] += half_open
            if v["first"] is None or first < v["first"]:
                v["first"] = first

            h = horiz[(client, port)]
            h["hosts"].add(server)
            h["half_open"] += half_open
            if h["first"] is None or first < h["first"]:
                h["first"] = first

        findings: list[Finding] = []
        for (client, server), v in vert.items():
            n = len(v["ports"])
            if n < self.MIN_TARGETS:
                continue
            ho_frac = v["half_open"] / n
            findings.append(
                self.finding(
                    title=f"Vertical port scan: {n} ports probed on {server}",
                    confidence=min(0.95, 0.6 + 0.3 * ho_frac),
                    src=client,
                    dst=server,
                    evidence={
                        "scan_type": "vertical",
                        "ports_scanned": n,
                        "half_open_ratio": round(ho_frac, 2),
                        "sample_ports": sorted(v["ports"])[:12],
                    },
                    packets=[v["first"]] if v["first"] is not None else [],
                )
            )
        for (client, port), h in horiz.items():
            n = len(h["hosts"])
            if n < self.MIN_TARGETS:
                continue
            ho_frac = h["half_open"] / n
            findings.append(
                self.finding(
                    title=f"Horizontal scan: port {port} swept across {n} hosts",
                    confidence=min(0.95, 0.6 + 0.3 * ho_frac),
                    src=client,
                    dst=None,
                    evidence={
                        "scan_type": "horizontal",
                        "target_port": port,
                        "hosts_scanned": n,
                        "half_open_ratio": round(ho_frac, 2),
                    },
                    packets=[h["first"]] if h["first"] is not None else [],
                )
            )
        return findings

"""Zerologon (CVE-2020-1472) — Netlogon authentication-bypass detection.

The exploit repeatedly calls NetrServerAuthenticate3 (Netlogon opnum 26) with an
all-zero client credential, brute-forcing the broken AES-CFB8 IV until the empty
session key is accepted (~256 tries on average). No legitimate client behaves
this way, so a burst of zero-credential Authenticate3 calls is high-confidence.
"""

from __future__ import annotations

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, is_all_zero_hex, layer

NETLOGON_AUTHENTICATE3_OPNUM = "26"


class ZerologonRule(Rule):
    id = "zerologon"
    name = "Zerologon authentication-bypass attempt (CVE-2020-1472)"
    severity = Severity.CRITICAL
    mitre = ["T1210"]
    confidence = 0.95
    description = (
        "Burst of NetrServerAuthenticate3 calls with an all-zero client "
        "credential against a domain controller."
    )

    # A handful of zero-credential Authenticate3 calls is already abnormal.
    THRESHOLD = 5

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        netlogon = layer(pkt, "rpc_netlogon", "netlogon")
        if netlogon is None:
            return []
        if field(netlogon, "netlogon_opnum", "opnum") != NETLOGON_AUTHENTICATE3_OPNUM:
            return []
        cred = field(netlogon, "netlogon_clientcred", "clientcred")
        if cred is None:
            return []  # the matching response carries servercred, not clientcred

        rec = ctx.scratch(self.id).setdefault(
            (pkt.src, pkt.dst),
            {"attempts": 0, "zero": 0, "computer": None, "frames": []},
        )
        rec["attempts"] += 1
        rec["frames"].append(pkt.number)
        computer = field(netlogon, "netlogon_computer_name", "computer_name")
        if computer:
            rec["computer"] = computer
        if is_all_zero_hex(cred):
            rec["zero"] += 1
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for (src, dst), rec in ctx.scratch(self.id).items():
            if rec["zero"] < self.THRESHOLD:
                continue
            all_zero = rec["zero"] == rec["attempts"]
            findings.append(
                self.finding(
                    title=(
                        f"Zerologon brute-force: {rec['zero']} NetrServerAuthenticate3 "
                        f"calls with an all-zero client credential"
                    ),
                    confidence=0.99 if all_zero else 0.9,
                    src=src,
                    dst=dst,
                    evidence={
                        "cve": "CVE-2020-1472",
                        "auth_attempts": rec["attempts"],
                        "zero_credential_attempts": rec["zero"],
                        "target_dc": rec["computer"],
                    },
                    packets=rec["frames"][:20],
                )
            )
        return findings

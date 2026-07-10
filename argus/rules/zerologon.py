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

        computer = field(netlogon, "netlogon_computer_name", "computer_name")
        ctx.window(self.id).add(
            (pkt.src, pkt.dst),
            pkt.ts,
            (is_all_zero_hex(cred), computer, pkt.number),
        )
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for (src, dst), obs in ctx.window(self.id).items():
            zero = sum(1 for o in obs if o[0])
            if zero < self.THRESHOLD:
                continue
            attempts = len(obs)
            computer = next((o[1] for o in reversed(obs) if o[1]), None)
            frames = [o[2] for o in obs]
            all_zero = zero == attempts
            findings.append(
                self.finding(
                    title=(
                        f"Zerologon brute-force: {zero} NetrServerAuthenticate3 "
                        f"calls with an all-zero client credential"
                    ),
                    confidence=0.99 if all_zero else 0.9,
                    src=src,
                    dst=dst,
                    evidence={
                        "cve": "CVE-2020-1472",
                        "auth_attempts": attempts,
                        "zero_credential_attempts": zero,
                        "target_dc": computer,
                    },
                    packets=frames[:20],
                )
            )
        return findings

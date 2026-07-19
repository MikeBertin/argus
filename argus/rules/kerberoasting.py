"""Kerberoasting detection (SPN service-ticket harvesting).

Any domain user can request a Kerberos service ticket (TGS) for *any* account
that has a Service Principal Name. The reply is encrypted with the service
account's password hash, so an attacker who collects tickets can crack them
offline — no further contact with the domain. Tools (Rubeus, GetUserSPNs)
therefore sweep many SPNs in one burst.

The sharpest part of the signal is the **encryption-type downgrade**: modern
domains issue AES tickets (etype 17/18), but RC4 (etype 23) is far cheaper to
crack, so roasting tools explicitly request it. RC4 alone is *not* enough to
alert on — legacy domains still use it legitimately — so this rule requires
both a burst of distinct SPNs *and* the weak-etype request.

Signal: one client requesting tickets for many distinct SPNs with RC4/DES
offered. ``krbtgt`` is excluded — TGS-REQs for it are ordinary referrals.
"""

from __future__ import annotations

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, field_values, layer

# TGS-REQ. NB: 12 is the *request*; 13 is the reply (TGS-REP).
MSG_TYPE_TGS_REQ = "12"

# Offline-crackable encryption types. 23/24 = RC4-HMAC (the roasting downgrade),
# 1/3 = legacy single-DES. AES (17/18) is absent by design — that is the
# non-suspicious case.
WEAK_ETYPES = {"1", "3", "23", "24"}

_ETYPE_NAMES = {
    "1": "des-cbc-crc",
    "3": "des-cbc-md5",
    "17": "aes128-cts-hmac-sha1-96",
    "18": "aes256-cts-hmac-sha1-96",
    "23": "rc4-hmac",
    "24": "rc4-hmac-exp",
}


class KerberoastingRule(Rule):
    id = "kerberoasting"
    name = "Kerberoasting (SPN ticket harvesting)"
    severity = Severity.HIGH
    mitre = ["T1558.003"]
    confidence = 0.85
    description = (
        "One client requesting service tickets for many distinct SPNs with a "
        "weak (RC4/DES) encryption type — offline-crackable ticket harvesting."
    )

    # Both thresholds must be met before the rule fires.
    MIN_SPNS = 5

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        krb = layer(pkt, "kerberos")
        if krb is None:
            return []
        if str(field(krb, "msg_type", default="")) != MSG_TYPE_TGS_REQ:
            return []

        # The SPN arrives as repeated SNameString components
        # ("MSSQLSvc", "db0.corp.local:1433") — getattr would yield only the
        # first, making every SPN look identical. Rebuild the whole name.
        parts = field_values(krb, "snamestring")
        if not parts:
            return []
        spn = "/".join(p.strip() for p in parts if p)
        if not spn or spn.split("/")[0].lower() == "krbtgt":
            return []  # TGT referral, not a service-ticket request

        etypes = {e.strip() for e in field_values(krb, "enctype") if e}
        weak = etypes & WEAK_ETYPES
        if not weak:
            return []  # AES-only request — the normal case

        ctx.window(self.id).add(
            pkt.src,
            pkt.ts,
            (spn, tuple(sorted(weak)), str(field(krb, "realm", default="") or "")),
            frame=pkt.number,
        )
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        store = ctx.window(self.id)
        for client, obs in store.items():
            spns = sorted({o[0] for o in obs})
            if len(spns) < self.MIN_SPNS:
                continue
            weak = sorted({e for o in obs for e in o[1]}, key=int)
            realms = sorted({o[2] for o in obs if o[2]})
            findings.append(
                self.finding(
                    title=(
                        f"Kerberoasting: {client} requested {len(spns)} distinct "
                        f"SPN tickets with weak encryption"
                    ),
                    confidence=min(0.97, self.confidence + 0.02 * len(spns)),
                    src=client,
                    dst=None,
                    evidence={
                        "client": client,
                        "distinct_spns": len(spns),
                        "spns_requested": spns[:15],
                        "weak_etypes": [
                            f"{e} ({_ETYPE_NAMES.get(e, 'unknown')})" for e in weak
                        ],
                        "realms": realms,
                        "requests": len(obs),
                    },
                    packets=[store.first_frame(client)],
                )
            )
        return findings

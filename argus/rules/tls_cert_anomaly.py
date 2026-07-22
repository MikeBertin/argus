"""Suspicious TLS server-certificate detection (self-signed / expired / placeholder).

A server's X.509 certificate travels in cleartext during a **TLS <=1.2**
handshake (the Certificate message; TLS 1.3 encrypts it, so this rule only sees
1.2-and-earlier). A few cheap, high-signal properties separate a throwaway
attacker / interception cert from a real one:

  * **self-signed** — issuer == subject, no CA vouches for it. The default for
    C2 servers, interception proxies and quick malware infrastructure.
  * **expired / not-yet-valid** — the validity window doesn't contain the
    capture time: a forgotten or carelessly minted cert.
  * **placeholder subject** — OpenSSL's default ``Internet Widgits Pty Ltd``
    (or an empty subject): a cert nobody bothered to fill in.

Scope, honestly stated: self-signed detection applies to a **single-certificate
presentation** (a genuine CA chain is by construction not self-signed — the leaf
is issued by an intermediate); validity and placeholder checks apply to the
end-entity (leaf) cert in any presentation.

Honest caveat: internal services, test rigs and appliances legitimately use
self-signed and even expired certs, so a *lone* anomaly is **MEDIUM**. **HIGH**
is reserved for the combination that characterises disposable attacker certs —
self-signed *and* (expired or placeholder), or any cert tripping two+ anomalies.
Operators whitelist known internal hosts downstream.
"""

from __future__ import annotations

from datetime import datetime, timezone

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field_values, layer

# OpenSSL's default self-signed subject — the classic "didn't fill it in" tell.
_PLACEHOLDER_MARKERS = ("internet widgits",)


def _epoch(utctime: str) -> float | None:
    """tshark renders X.509 times as 'YYYY-MM-DD HH:MM:SS (UTC)'. Parse to epoch
    seconds; return None on any unexpected shape so a check simply abstains."""
    s = utctime.replace("(UTC)", "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def _symmetric(values: list[str]) -> bool:
    """True if a DN-attribute list is two identical halves (issuer == subject).

    In a certificate's DER the issuer RDNs precede the subject RDNs, and pyshark
    flattens both into one ordered list. A self-signed cert repeats the same
    attributes for issuer and subject, so the list splits into equal halves —
    and it does so identically within each string-encoding field, which is why
    this stays correct regardless of how the DN mixes UTF8/PrintableString."""
    n = len(values)
    return n % 2 == 0 and values[: n // 2] == values[n // 2 :]


class TlsCertAnomalyRule(Rule):
    id = "tls_cert_anomaly"
    name = "Suspicious TLS certificate (self-signed/expired/placeholder)"
    severity = Severity.MEDIUM  # a lone anomaly; elevated to HIGH in combination
    mitre = ["T1587.003"]
    confidence = 0.7
    description = (
        "A TLS server certificate that is self-signed, expired/not-yet-valid, "
        "or carries a placeholder subject — throwaway attacker-cert tells."
    )

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        tls = layer(pkt, "tls")
        if tls is None:
            return []
        # Presence of a validity period is our "this packet carries a cert" test
        # — more robust than handshake_type when several messages coalesce.
        utctimes = field_values(tls, "x509af_utctime")
        if len(utctimes) < 2:
            return []

        serials = field_values(tls, "x509af_serialnumber")
        n_certs = len(serials) or len(utctimes) // 2
        utf8 = field_values(tls, "x509sat_utf8string")
        printable = field_values(tls, "x509sat_printablestring")
        dn_values = utf8 + printable

        anomalies: list[str] = []

        # Leaf (end-entity) cert is first in the message: utctimes[0]=notBefore,
        # utctimes[1]=notAfter. Clock is the packet timestamp (replay-safe).
        not_before, not_after = _epoch(utctimes[0]), _epoch(utctimes[1])
        if not_after is not None and not_after < pkt.ts:
            anomalies.append("expired")
        if not_before is not None and not_before > pkt.ts:
            anomalies.append("not_yet_valid")

        if any(m in v.lower() for v in dn_values for m in _PLACEHOLDER_MARKERS):
            anomalies.append("placeholder_subject")

        # Self-signed only means anything for a single-cert presentation.
        subject = issuer = None
        if n_certs == 1 and _symmetric(utf8) and _symmetric(printable) and dn_values:
            anomalies.append("self_signed")
            hi, hp = len(utf8) // 2, len(printable) // 2
            issuer = ", ".join(utf8[:hi] + printable[:hp])
            subject = ", ".join(utf8[hi:] + printable[hp:])

        if not anomalies:
            return []

        serial = serials[0] if serials else "?"
        ctx.window(self.id).add(
            (pkt.src, pkt.dst, serial),
            pkt.ts,
            (tuple(anomalies), subject, issuer),
            frame=pkt.number,
        )
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        store = ctx.window(self.id)
        for (server, client, serial), obs in store.items():
            anomalies, subject, issuer = obs[-1]
            aset = set(anomalies)

            strong = "self_signed" in aset and (
                "expired" in aset or "placeholder_subject" in aset
            )
            severity = (
                Severity.HIGH if strong or len(anomalies) >= 2 else Severity.MEDIUM
            )
            confidence = min(0.95, self.confidence + 0.1 * len(anomalies))

            findings.append(
                self.finding(
                    title=(
                        f"Suspicious TLS certificate ({', '.join(anomalies)}) "
                        f"from {server}"
                    ),
                    severity=severity,
                    confidence=confidence,
                    src=server,
                    dst=client,
                    evidence={
                        "server": server,
                        "client": client,
                        "anomalies": list(anomalies),
                        "subject": subject,
                        "issuer": issuer,
                        "serial": serial,
                    },
                    packets=[store.first_frame((server, client, serial))],
                )
            )
        return findings

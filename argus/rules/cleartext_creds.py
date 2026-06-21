"""Cleartext-credential exposure over HTTP.

Flags credentials transmitted without TLS: HTTP Basic ``Authorization`` headers
and login form fields (``password``/``passwd``/``pwd``) in POST bodies. Ordinary
browsing and non-credential form posts (e.g. a search box) do not trip it.
"""

from __future__ import annotations

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, layer

CRED_FIELD_NAMES = ("password=", "passwd=", "pwd=", "pass=")


def _decode_hex(value: str | None) -> str:
    if not value:
        return ""
    try:
        return bytes.fromhex(value.replace(":", "")).decode("latin-1")
    except ValueError:
        return ""


class CleartextCredsRule(Rule):
    id = "cleartext_creds"
    name = "Cleartext credentials over HTTP"
    severity = Severity.MEDIUM
    mitre = ["T1040"]
    confidence = 0.9
    description = "HTTP Basic auth or login-form credentials sent without TLS."

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        http = layer(pkt, "http")
        if http is None:
            return []
        findings: list[Finding] = []
        host = field(http, "host", default="")
        uri = field(http, "request_uri", default="")

        # 1) HTTP Basic Authorization header
        authbasic = field(http, "authbasic")
        authorization = field(http, "authorization", default="")
        if authbasic or str(authorization).lower().startswith("basic"):
            user = str(authbasic).split(":", 1)[0] if authbasic else None
            findings.append(
                self.finding(
                    title="HTTP Basic credentials sent in cleartext",
                    confidence=0.95,
                    src=pkt.src,
                    dst=pkt.dst,
                    evidence={"host": host, "uri": uri, "username": user},
                    packets=[pkt.number],
                )
            )

        # 2) Login-form credentials in a POST body
        body = _decode_hex(field(http, "file_data")).lower()
        if field(http, "request_method") == "POST" and any(
            name in body for name in CRED_FIELD_NAMES
        ):
            findings.append(
                self.finding(
                    title="Login-form password submitted in cleartext (HTTP POST)",
                    confidence=0.9,
                    src=pkt.src,
                    dst=pkt.dst,
                    evidence={"host": host, "uri": uri},
                    packets=[pkt.number],
                )
            )
        return findings

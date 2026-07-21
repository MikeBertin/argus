"""SMB lateral movement detection (PsExec-style service-binary drop).

The classic remote-execution pivot (PsExec, smbexec, Impacket, many RATs) writes
a service executable to a victim's **administrative disk share** — ``ADMIN$``
(maps to ``C:\\Windows``) or a drive share like ``C$`` — and then creates a
service to run it. The network-visible half is the file drop: an executable
written to an admin disk share.

The discriminator matters. Ordinary Active Directory RPC — including Zerologon's
own traffic — runs over ``IPC$`` using named pipes (``svcctl``, ``samr``), which
is *not* a disk share and carries no executable. Grounding against the real
``zerologon.pcap`` confirmed it only ever touches ``IPC$``; requiring an
**executable on an admin *disk* share** is what keeps this rule off legitimate
RPC and off normal file-share access to non-admin shares.

Signal: one host creating/writing an executable file on another host's admin
disk share (ADMIN$ / C$ / <drive>$), IPC$ excluded.
"""

from __future__ import annotations

import re

from argus.context import AnalysisContext
from argus.models import Finding, NormalizedPacket, Rule, Severity
from argus.rules._util import field, layer, truthy

# smb2.cmd values we care about: Create opens/creates a file, Write sends bytes.
SMB2_CREATE = "5"
SMB2_WRITE = "9"

# Executable / code payloads dropped for execution.
_EXE_SUFFIXES = (".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".com")

# Admin disk share = "ADMIN$" or a single drive letter + "$" (C$, D$...).
# IPC$ (named-pipe share) is deliberately NOT matched — that is normal RPC.
_ADMIN_SHARE = re.compile(r"^(admin|[a-z])\$$", re.IGNORECASE)


def _share_name(tree: str | None) -> str | None:
    """Last component of a UNC tree path: '\\\\HOST\\ADMIN$' -> 'ADMIN$'."""
    if not tree:
        return None
    return tree.replace("/", "\\").rstrip("\\").split("\\")[-1] or None


class SmbLateralRule(Rule):
    id = "smb_lateral"
    name = "SMB lateral movement (PsExec service-binary drop)"
    severity = Severity.HIGH
    mitre = ["T1021.002", "T1570"]
    confidence = 0.8
    description = (
        "One host writing an executable to another's admin disk share "
        "(ADMIN$/C$) — PsExec-style remote service-binary drop."
    )

    def inspect_packet(
        self, pkt: NormalizedPacket, ctx: AnalysisContext
    ) -> list[Finding]:
        smb = layer(pkt, "smb2")
        if smb is None:
            return []
        cmd = str(field(smb, "cmd", default=""))
        if cmd not in (SMB2_CREATE, SMB2_WRITE):
            return []
        # Responses echo the tree + filename; counting them would invent a
        # phantom finding in the reverse direction (server "dropping" onto the
        # client). Only the client's request direction is the drop.
        if truthy(field(smb, "flags_response")):
            return []

        share = _share_name(field(smb, "tree"))
        if not share or not _ADMIN_SHARE.match(share):
            return []  # IPC$ / normal shares / no tree bound

        fname = field(smb, "filename")
        if not fname or not str(fname).lower().endswith(_EXE_SUFFIXES):
            return []  # not an executable payload

        ctx.window(self.id).add(
            (pkt.src, pkt.dst),
            pkt.ts,
            (share, str(fname), cmd),
            frame=pkt.number,
        )
        return []

    def finalize(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        store = ctx.window(self.id)
        for (src, dst), obs in store.items():
            files = sorted({o[1] for o in obs})
            shares = sorted({o[0] for o in obs})
            # A Write (bytes actually landing) is a stronger signal than a bare
            # open; boost confidence when one is present.
            wrote = any(o[2] == SMB2_WRITE for o in obs)
            conf = min(0.97, self.confidence + (0.1 if wrote else 0.0))
            findings.append(
                self.finding(
                    title=(
                        f"SMB lateral movement: {src} dropped "
                        f"{'/'.join(files[:3])} on {dst} {'/'.join(shares)}"
                    ),
                    confidence=conf,
                    src=src,
                    dst=dst,
                    evidence={
                        "src": src,
                        "dst": dst,
                        "admin_shares": shares,
                        "executables": files[:15],
                        "bytes_written": wrote,
                    },
                    packets=[store.first_frame((src, dst))],
                )
            )
        return findings

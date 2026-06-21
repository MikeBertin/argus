"""MITRE ATT&CK technique metadata.

A small static lookup covering the techniques ARGUS rules emit, used to enrich
the HTML report (technique name, tactic, and a deep-link to attack.mitre.org).
Unknown ids degrade gracefully so new rules don't break the report.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str


# Keyed by ATT&CK id. Sub-techniques use the "Txxxx.yyy" form.
TECHNIQUES: dict[str, Technique] = {
    "T1210": Technique("T1210", "Exploitation of Remote Services", "Lateral Movement"),
    "T1071": Technique("T1071", "Application Layer Protocol", "Command and Control"),
    "T1071.004": Technique("T1071.004", "DNS", "Command and Control"),
    "T1048.003": Technique(
        "T1048.003",
        "Exfiltration Over Unencrypted Non-C2 Protocol",
        "Exfiltration",
    ),
    "T1040": Technique("T1040", "Network Sniffing", "Credential Access"),
    "T1046": Technique("T1046", "Network Service Discovery", "Discovery"),
    "T1110": Technique("T1110", "Brute Force", "Credential Access"),
    "T1557.002": Technique("T1557.002", "ARP Cache Poisoning", "Credential Access"),
}


def technique_url(technique_id: str) -> str:
    """Canonical attack.mitre.org URL, including sub-technique paths."""
    base = technique_id.split(".")
    if len(base) == 2:
        return f"https://attack.mitre.org/techniques/{base[0]}/{base[1]}/"
    return f"https://attack.mitre.org/techniques/{technique_id}/"


def lookup(technique_id: str) -> Technique:
    """Return metadata, falling back to a minimal record for unknown ids."""
    known = TECHNIQUES.get(technique_id)
    if known is not None:
        return known
    return Technique(technique_id, technique_id, "Other")

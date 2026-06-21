"""Each rule must fire on its positive fixture and stay silent on benign ones.

The benign assertions are the important half: false-positive resistance is what
separates a detection engine from a pile of greps.
"""

from pathlib import Path

import pytest
from conftest import PCAPS

from argus.engine import Engine
from argus.models import Severity

# fixture path (relative to fixtures/pcaps) -> rule id that must fire
POSITIVES = {
    "zerologon.pcap": "zerologon",
    "generated/dns_tunnel.pcap": "dns_tunnel",
    "generated/icmp_exfil.pcap": "icmp_exfil",
    "generated/cleartext_login.pcap": "cleartext_creds",
    "generated/beaconing.pcap": "beaconing",
    "generated/port_scan_vertical.pcap": "port_scan",
    "generated/port_scan_horizontal.pcap": "port_scan",
    "generated/arp_spoof.pcap": "arp_spoof",
    "generated/bruteforce_smb.pcap": "bruteforce",
    "generated/bruteforce_rdp.pcap": "bruteforce",
    "generated/tls_ja3.pcap": "ja3_fingerprint",
}

# benign captures that must produce zero findings
BENIGN = ["http.cap", "nb6-startup.pcap", "dns+icmp.pcapng"]


def _ensure_generated():
    if not (PCAPS / "generated" / "dns_tunnel.pcap").exists():
        import fixtures.generate as gen  # noqa: WPS433

        gen.main()


@pytest.fixture(scope="session", autouse=True)
def _fixtures_present():
    _ensure_generated()


@pytest.mark.parametrize("fixture,rule_id", POSITIVES.items())
def test_positive_fixture_fires(fixture: str, rule_id: str):
    result = Engine().analyze(str(PCAPS / fixture))
    fired = {f.rule_id for f in result.findings}
    assert rule_id in fired, f"{rule_id} did not fire on {fixture} (got {fired})"


@pytest.mark.parametrize("fixture", BENIGN)
def test_benign_fixture_silent(fixture: str):
    result = Engine().analyze(str(PCAPS / fixture))
    assert result.findings == [], (
        f"false positive(s) on benign {fixture}: "
        f"{[(f.rule_id, f.severity.name) for f in result.findings]}"
    )


def test_zerologon_does_not_trigger_port_scan():
    """zerologon hits 66 RPC ports but they are established connections, not a scan."""
    result = Engine().analyze(str(PCAPS / "zerologon.pcap"))
    fired = {f.rule_id for f in result.findings}
    assert "port_scan" not in fired, "RPC dynamic ports falsely flagged as a port scan"


def test_zerologon_does_not_trigger_bruteforce():
    """zerologon opens only 2 SMB connections — well under the brute-force threshold."""
    result = Engine().analyze(str(PCAPS / "zerologon.pcap"))
    assert "bruteforce" not in {f.rule_id for f in result.findings}


def test_bruteforce_does_not_overlap_scan_or_beacon():
    """Established login connections must read as brute-force only, not scan/beacon."""
    result = Engine().analyze(str(PCAPS / "generated/bruteforce_smb.pcap"))
    fired = {f.rule_id for f in result.findings}
    assert fired == {"bruteforce"}, f"unexpected overlap: {fired}"


def test_zerologon_is_critical_and_attributed():
    result = Engine().analyze(str(PCAPS / "zerologon.pcap"))
    zl = next(f for f in result.findings if f.rule_id == "zerologon")
    assert zl.severity is Severity.CRITICAL
    assert "T1210" in zl.mitre
    assert zl.evidence["target_dc"] == "DC01"
    assert zl.evidence["zero_credential_attempts"] >= 5

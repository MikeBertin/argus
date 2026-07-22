"""Each rule must fire on its positive fixture and stay silent on benign ones.

The benign assertions are the important half: false-positive resistance is what
separates a detection engine from a pile of greps.
"""

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
    "generated/tls_fingerprint.pcap": "tls_fingerprint",
    "generated/llmnr_spoof.pcap": "llmnr_spoof",
    "generated/rogue_dhcp.pcap": "rogue_dhcp",
    "generated/kerberoasting.pcap": "kerberoasting",
    "generated/smb_lateral.pcap": "smb_lateral",
    "generated/dns_zone_transfer.pcap": "dns_zone_transfer",
    "generated/tls_cert_anomaly.pcap": "tls_cert_anomaly",
}

# benign captures that must produce zero findings
BENIGN = ["http.cap", "nb6-startup.pcap", "dns+icmp.pcapng"]


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


def test_redundant_dhcp_servers_do_not_trigger_rogue_dhcp():
    """nb6-startup has two DHCP server-ids offering the SAME gateway (legit ISP
    redundancy) — the conflict-based rule must not flag it."""
    result = Engine().analyze(str(PCAPS / "nb6-startup.pcap"))
    assert "rogue_dhcp" not in {f.rule_id for f in result.findings}


def test_zerologon_does_not_trigger_bruteforce():
    """zerologon opens only 2 SMB connections — well under the brute-force threshold."""
    result = Engine().analyze(str(PCAPS / "zerologon.pcap"))
    assert "bruteforce" not in {f.rule_id for f in result.findings}


def test_bruteforce_does_not_overlap_scan_or_beacon():
    """Established login connections must read as brute-force only, not scan/beacon."""
    result = Engine().analyze(str(PCAPS / "generated/bruteforce_smb.pcap"))
    fired = {f.rule_id for f in result.findings}
    assert fired == {"bruteforce"}, f"unexpected overlap: {fired}"


def test_aes_ticket_requests_do_not_trigger_kerberoasting():
    """The FP guard that matters for this rule: a normal workstation asking for
    the same *shape* of traffic (one client, several distinct SPNs) but with AES
    encryption — plus a krbtgt referral offering RC4, which is routine. Only the
    weak-etype half of the signal is absent, so silence proves the rule needs
    both halves and isn't just counting TGS-REQs."""
    result = Engine().analyze(str(PCAPS / "generated/kerberos_benign.pcap"))
    assert result.findings == [], (
        f"false positive on benign Kerberos: "
        f"{[(f.rule_id, f.severity.name) for f in result.findings]}"
    )


def test_kerberoasting_reconstructs_full_spns_and_flags_rc4():
    """SNameString is a *repeated* field — a naive getattr yields only the first
    component, making every SPN look identical and collapsing the distinct-SPN
    count to 1. Assert the full service/host SPNs survive."""
    result = Engine().analyze(str(PCAPS / "generated/kerberoasting.pcap"))
    kr = next(f for f in result.findings if f.rule_id == "kerberoasting")
    assert kr.severity is Severity.HIGH
    assert "T1558.003" in kr.mitre
    assert kr.evidence["distinct_spns"] >= 5
    assert "MSSQLSvc/db01.corp.local:1433" in kr.evidence["spns_requested"]
    assert any("rc4" in e for e in kr.evidence["weak_etypes"])


def test_normal_file_share_write_does_not_trigger_smb_lateral():
    """A normal file copy to an ordinary (non-admin) share must stay silent —
    the rule keys on admin-disk-share + executable, not on SMB writes at large."""
    result = Engine().analyze(str(PCAPS / "generated/smb_benign.pcap"))
    assert "smb_lateral" not in {f.rule_id for f in result.findings}


def test_zerologon_ipc_rpc_does_not_trigger_smb_lateral():
    """zerologon's SMB is all IPC$/svcctl/samr named-pipe RPC — no admin disk
    share, no executable. It must not read as a service-binary drop."""
    result = Engine().analyze(str(PCAPS / "zerologon.pcap"))
    assert "smb_lateral" not in {f.rule_id for f in result.findings}


def test_smb_lateral_flags_admin_share_exe_write():
    result = Engine().analyze(str(PCAPS / "generated/smb_lateral.pcap"))
    lm = next(f for f in result.findings if f.rule_id == "smb_lateral")
    assert lm.severity is Severity.HIGH
    assert "T1021.002" in lm.mitre
    assert "PSEXESVC.exe" in lm.evidence["executables"]
    assert lm.evidence["admin_shares"] == ["ADMIN$"]
    assert lm.evidence["bytes_written"] is True


@pytest.mark.parametrize("exe_on_write", [True, False], ids=["tshark4.6", "tshark4.2"])
def test_smb_lateral_is_robust_to_tshark_filename_binding(exe_on_write):
    """Regression for a real CI-only failure: tshark binds the FID->filename to
    different frames by version — the Write on 4.6.x, the Create on 4.2.2 — while
    the TID->tree binding is stable on both. The rule must report the same verdict
    (exe identified, bytes_written True) regardless of which frame carried the
    name. No pcap fixture can force the older binding, so drive finalize directly."""
    from argus.context import AnalysisContext
    from argus.rules.smb_lateral import SmbLateralRule

    rule = SmbLateralRule()
    ctx = AnalysisContext()
    win = ctx.window(rule.id)
    key = ("10.0.0.66", "10.0.0.20")
    # Create carries the name only on the older tshark; Write carries it only on
    # the newer one. Exactly one of the two frames has the filename resolved.
    win.add(key, 1.0, ("ADMIN$", None if exe_on_write else "PSEXESVC.exe", "5"), frame=3)
    win.add(key, 1.1, ("ADMIN$", "PSEXESVC.exe" if exe_on_write else None, "9"), frame=5)

    findings = rule.finalize(ctx)
    assert len(findings) == 1
    assert findings[0].evidence["executables"] == ["PSEXESVC.exe"]
    assert findings[0].evidence["bytes_written"] is True


def test_normal_dns_over_tcp_does_not_trigger_zone_transfer():
    """Ordinary DNS-over-TCP (large/DNSSEC responses use TCP too) must stay
    silent — the rule keys on the AXFR/IXFR qtype, not on the transport."""
    result = Engine().analyze(str(PCAPS / "generated/dns_over_tcp_benign.pcap"))
    assert "dns_zone_transfer" not in {f.rule_id for f in result.findings}


def test_dns_zone_transfer_success_is_high_and_attributed():
    result = Engine().analyze(str(PCAPS / "generated/dns_zone_transfer.pcap"))
    zt = next(f for f in result.findings if f.rule_id == "dns_zone_transfer")
    assert zt.severity is Severity.HIGH  # elevated because the transfer succeeded
    assert "T1590.002" in zt.mitre
    assert zt.evidence["zone"] == "corp.local"
    assert zt.evidence["transfer_type"] == "AXFR"
    assert zt.evidence["succeeded"] is True
    assert zt.evidence["records_transferred"] >= 5


def test_ca_issued_in_date_cert_does_not_trigger_tls_cert_anomaly():
    """A CA-issued (issuer != subject), in-date, real-subject leaf cert must stay
    silent — proves the rule keys on cert anomalies, not on TLS certs at large."""
    result = Engine().analyze(str(PCAPS / "generated/tls_cert_benign.pcap"))
    assert "tls_cert_anomaly" not in {f.rule_id for f in result.findings}


def test_tls_cert_anomaly_flags_selfsigned_expired_placeholder():
    result = Engine().analyze(str(PCAPS / "generated/tls_cert_anomaly.pcap"))
    ca = next(f for f in result.findings if f.rule_id == "tls_cert_anomaly")
    assert ca.severity is Severity.HIGH  # self-signed + expired -> the strong combo
    assert "T1587.003" in ca.mitre
    assert {"self_signed", "expired", "placeholder_subject"} <= set(
        ca.evidence["anomalies"]
    )
    # self-signed: reconstructed issuer and subject DNs are identical
    assert ca.evidence["subject"] == ca.evidence["issuer"]


def test_tls_cert_single_anomaly_is_medium():
    """A lone anomaly (e.g. an expired but CA-issued cert) is MEDIUM, not HIGH —
    the honest-caveat tier. Driven through finalize so the severity logic is
    tested without minting yet another cert fixture."""
    from argus.context import AnalysisContext
    from argus.rules.tls_cert_anomaly import TlsCertAnomalyRule

    rule = TlsCertAnomalyRule()
    ctx = AnalysisContext()
    ctx.window(rule.id).add(
        ("203.0.113.9", "10.0.0.50", "ab"), 1.0,
        (("expired",), "CN=host.example", "CN=Real CA"), frame=1,
    )
    findings = rule.finalize(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].evidence["anomalies"] == ["expired"]


def test_selfsigned_dn_halves_primitive():
    """issuer == subject shows up as a DN-attribute list of two equal halves,
    regardless of string encoding — the core self-signed test."""
    from argus.rules.tls_cert_anomaly import _symmetric

    assert _symmetric(["Internet Widgits", "Internet Widgits"]) is True
    assert _symmetric([]) is True  # vacuously symmetric (that encoding unused)
    assert _symmetric(["Root CA", "Trust", "www.example.com", "Corp"]) is False
    assert _symmetric(["only-one"]) is False  # odd length can't be two halves


def test_zerologon_is_critical_and_attributed():
    result = Engine().analyze(str(PCAPS / "zerologon.pcap"))
    zl = next(f for f in result.findings if f.rule_id == "zerologon")
    assert zl.severity is Severity.CRITICAL
    assert "T1210" in zl.mitre
    assert zl.evidence["target_dc"] == "DC01"
    assert zl.evidence["zero_credential_attempts"] >= 5

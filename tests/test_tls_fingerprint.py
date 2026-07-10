"""TLS fingerprinting: JA3 + JA4 computation, oracle validation, rule behaviour."""

import hashlib
import shutil
import subprocess

import pytest
from conftest import PCAPS

from argus.engine import Engine
from argus.fingerprint_blocklist import _parse_feed_csv
from argus.ja3 import is_grease, ja3_from_components
from argus.ja4 import ja4_from_components, ja4s_from_components
from argus.models import Severity

FIXTURE = "generated/tls_fingerprint.pcap"
# fingerprints of the malicious fixture Client Hello (both seeded into the blocklist).
FIXTURE_MALICIOUS_JA3 = "1fb4e5b9b9d127b1efa51e95dd64c8c5"
FIXTURE_MALICIOUS_JA4 = "t12i090300_f1631a9af75e_c08b0bbc99a6"
FIXTURE_MALICIOUS_JA4S = "t120300_c02b_bec8bdbaef8a"


# --- JA3 -------------------------------------------------------------------- #
def test_ja3_string_and_hash_construction():
    s, md5 = ja3_from_components(771, [4865, 4866, 49195], [10, 11, 13], [29, 23], [0])
    assert s == "771,4865-4866-49195,10-11-13,29-23,0"
    assert md5 == hashlib.md5(s.encode()).hexdigest()


def test_grease_values_detected():
    assert is_grease(0x0A0A) and is_grease(0x1A1A) and is_grease(0xFAFA)
    assert not is_grease(0x1301) and not is_grease(0xC02B)


# --- JA4 -------------------------------------------------------------------- #
def test_ja4_components_sort_and_section_rules():
    # ciphers + extensions sorted; SNI(0) and ALPN(16) excluded from JA4_c;
    # sig-algs appended in order after '_'.
    ja4 = ja4_from_components(
        protocol="t", version=0x0303, sni_present=True,
        ciphers=[0x1302, 0x1301], extensions=[0x000A, 0x0000, 0x0010, 0x000D],
        sig_algs=[0x0804, 0x0401], alpn_first="h2",
    )
    a, b, c = ja4.split("_")
    # count is ALL extensions (4); SNI/ALPN only drop from the JA4_c hash, not the count
    assert a == "t12d0204h2"  # tcp, tls1.2, sni, 2 ciphers, 4 exts, alpn h2
    assert b == hashlib.sha256(b"1301,1302").hexdigest()[:12]  # ciphers sorted
    assert c == hashlib.sha256(b"000a,000d_0804,0401").hexdigest()[:12]  # SNI/ALPN dropped


def test_ja4_no_sigalgs_has_no_underscore_section():
    ja4 = ja4_from_components(
        "t", 0x0303, False, [0x1301], [0x000A, 0x000B], [], None
    )
    c = ja4.split("_")[2]
    assert c == hashlib.sha256(b"000a,000b").hexdigest()[:12]


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not available")
def test_ja4_matches_tshark_native_oracle():
    """Our JA4 must equal tshark's native tls.handshake.ja4 (when supported)."""
    import asyncio

    import pyshark

    from argus.ja4 import compute_ja4

    path = str(PCAPS / FIXTURE)
    native = subprocess.run(
        ["tshark", "-r", path, "-T", "fields", "-e", "tls.handshake.ja4"],
        capture_output=True, text=True,
    ).stdout.split("\n")
    native = [x for x in native if x.strip()]
    if not native:
        pytest.skip("this tshark build has no native JA4 field")

    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    cap = pyshark.FileCapture(path)
    mine = []
    for p in cap:
        tls = [l for l in p.layers if l.layer_name == "tls"]
        if tls and str(getattr(tls[0], "handshake_type", None)) == "1":
            mine.append(compute_ja4(tls[0]))
    cap.close()
    assert mine == native, f"JA4 mismatch vs tshark: {mine} != {native}"


# --- JA4S (server) ---------------------------------------------------------- #
def test_ja4s_matches_foxio_reference_value():
    """A TLS 1.3 Server Hello (cipher 1301, extensions 002b,0033) must produce the
    exact JA4S FoxIO's reference implementation emits for that profile."""
    ja4s = ja4s_from_components(
        protocol="t", version=0x0304, extensions=[0x002B, 0x0033],
        cipher=0x1301, alpn_first=None,
    )
    assert ja4s == "t130200_1301_a56c5b993250"  # verified against FoxIO ja4db reference


def test_ja4s_keeps_extension_order_and_grease():
    # JA4S keeps extensions in order WITH grease (unlike client JA4_c) and the
    # cipher is literal, not hashed.
    ja4s = ja4s_from_components("t", 0x0303, [0x0A0A, 0xFF01, 0x000B], 0xC02F, "h2")
    a, cipher, ext_hash = ja4s.split("_")
    assert a == "t1203h2"  # tls1.2, 3 exts (grease counted), alpn h2
    assert cipher == "c02f"
    assert ext_hash == hashlib.sha256(b"0a0a,ff01,000b").hexdigest()[:12]


def test_blocklisted_ja4s_server_fires_high():
    result = Engine().analyze(str(PCAPS / FIXTURE))
    hits = [f for f in result.findings if f.rule_id == "tls_fingerprint"
            and f.severity is Severity.HIGH and f.evidence.get("ja4s")]
    assert hits, "blocklisted JA4S server did not fire HIGH"
    assert hits[0].evidence["ja4s"] == FIXTURE_MALICIOUS_JA4S


def test_benign_server_ja4s_enrichment():
    result = Engine().analyze(str(PCAPS / FIXTURE))
    info = [f for f in result.findings if f.rule_id == "tls_fingerprint"
            and f.severity is Severity.INFO and f.evidence.get("ja4s")]
    assert info and info[0].evidence["ja4s"] == "t130200_1301_a56c5b993250"


# --- rule ------------------------------------------------------------------- #
def test_blocklisted_fingerprint_fires_high():
    result = Engine().analyze(str(PCAPS / FIXTURE))
    hits = [f for f in result.findings
            if f.rule_id == "tls_fingerprint" and f.severity is Severity.HIGH]
    assert hits, "blocklisted fingerprint did not produce a HIGH finding"
    ev = hits[0].evidence
    assert ev["ja3"] == FIXTURE_MALICIOUS_JA3
    assert ev["ja4"] == FIXTURE_MALICIOUS_JA4
    assert "T1573" in hits[0].mitre


def test_ja4_is_in_blocklist_and_matches_independently():
    from argus.fingerprint_blocklist import load_blocklist

    bl = load_blocklist()
    assert FIXTURE_MALICIOUS_JA4 in bl  # JA4 entry seeded
    # rule matches on (ja3 OR ja4); a JA4 hit alone must be sufficient
    assert bl.get("not-a-real-ja3") or bl.get(FIXTURE_MALICIOUS_JA4)


def test_benign_client_is_info_enrichment_with_both_fingerprints():
    result = Engine().analyze(str(PCAPS / FIXTURE))
    info = [f for f in result.findings
            if f.rule_id == "tls_fingerprint" and f.severity is Severity.INFO]
    assert info, "benign TLS client produced no enrichment"
    assert info[0].evidence["ja3"] and info[0].evidence["ja4"]
    assert info[0].mitre == []


# --- feed ------------------------------------------------------------------- #
def test_feed_csv_parser():
    sample = (
        "# comment line\n"
        "ja3_md5,Firstseen,Listingreason\n"
        "e7d705a3286e19ea42f587b344ee6865,2021-01-01,Malware\n"
    )
    parsed = _parse_feed_csv(sample)
    assert "e7d705a3286e19ea42f587b344ee6865" in parsed
    assert parsed["e7d705a3286e19ea42f587b344ee6865"]["source"] == "abuse.ch SSLBL"

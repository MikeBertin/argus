"""JA3 computation + fingerprint rule (detection and enrichment)."""

import hashlib

from conftest import PCAPS

from argus.engine import Engine
from argus.ja3 import ja3_from_components, is_grease
from argus.ja3_blocklist import _parse_feed_csv
from argus.models import Severity

# JA3 md5 of the malicious fixture Client Hello (seeded into the blocklist).
FIXTURE_MALICIOUS_JA3 = "1fb4e5b9b9d127b1efa51e95dd64c8c5"


def test_ja3_string_and_hash_construction():
    # version, ciphers, extensions, curves, point-formats
    s, md5 = ja3_from_components(
        771, [4865, 4866, 49195], [10, 11, 13], [29, 23], [0]
    )
    assert s == "771,4865-4866-49195,10-11-13,29-23,0"
    assert md5 == hashlib.md5(s.encode()).hexdigest()
    assert len(md5) == 32


def test_grease_values_detected():
    assert is_grease(0x0A0A) and is_grease(0x1A1A) and is_grease(0xFAFA)
    assert not is_grease(0x1301) and not is_grease(0xC02B)


def test_ja3_grease_excluded_from_components():
    # GREASE ciphers/extensions must be dropped before hashing.
    clean, _ = ja3_from_components(771, [4865], [10], [29], [0])
    # (component builder itself does not filter; the pyshark extractor does —
    # this asserts the canonical string shape the extractor must produce.)
    assert clean == "771,4865,10,29,0"


def test_blocklisted_ja3_fires_high():
    result = Engine().analyze(str(PCAPS / "generated/tls_ja3.pcap"))
    hits = [f for f in result.findings if f.rule_id == "ja3_fingerprint"
            and f.severity is Severity.HIGH]
    assert hits, "blocklisted JA3 did not produce a HIGH finding"
    assert hits[0].evidence["ja3"] == FIXTURE_MALICIOUS_JA3
    assert "T1573" in hits[0].mitre


def test_benign_ja3_is_info_enrichment():
    result = Engine().analyze(str(PCAPS / "generated/tls_ja3.pcap"))
    info = [f for f in result.findings if f.rule_id == "ja3_fingerprint"
            and f.severity is Severity.INFO]
    assert info, "benign TLS client produced no JA3 enrichment"
    assert info[0].mitre == []


def test_feed_csv_parser():
    sample = (
        "# comment line\n"
        "ja3_md5,Firstseen,Listingreason\n"
        "e7d705a3286e19ea42f587b344ee6865,2021-01-01,Malware\n"
    )
    parsed = _parse_feed_csv(sample)
    assert "e7d705a3286e19ea42f587b344ee6865" in parsed
    assert parsed["e7d705a3286e19ea42f587b344ee6865"]["source"] == "abuse.ch SSLBL"

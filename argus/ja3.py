"""JA3 TLS client fingerprinting.

JA3 (Althouse/Atkinson/Salesforce) fingerprints a TLS Client Hello by hashing a
comma-separated string of its decimal fields:

    SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

where each group is dash-joined. GREASE values (RFC 8701) are excluded from
ciphers, extensions and curves. The MD5 of that string is the JA3 hash. It
identifies the *client stack* independent of IP/SNI — useful because many malware
families ship a distinctive, stable TLS fingerprint.
"""

from __future__ import annotations

import hashlib


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE values: 0x0a0a, 0x1a1a, ... 0xfafa."""
    return (value & 0x0F0F) == 0x0A0A


def _to_int(text: str) -> int:
    text = text.strip()
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def _join(values: list[int]) -> str:
    return "-".join(str(v) for v in values)


def ja3_from_components(
    version: int,
    ciphers: list[int],
    extensions: list[int],
    curves: list[int],
    point_formats: list[int],
) -> tuple[str, str]:
    """Build the JA3 string and its MD5 from already-parsed components."""
    ja3_str = ",".join(
        [
            str(version),
            _join(ciphers),
            _join(extensions),
            _join(curves),
            _join(point_formats),
        ]
    )
    return ja3_str, hashlib.md5(ja3_str.encode()).hexdigest()


# --- pyshark extraction ---------------------------------------------------- #
def _one_int(tls, name: str) -> int | None:
    try:
        return _to_int(getattr(tls, name))
    except (AttributeError, TypeError, ValueError):
        return None


def _all_ints(tls, name: str, drop_grease: bool = True) -> list[int]:
    container = tls.get_field(name)
    if container is None:
        return []
    out: list[int] = []
    for fld in container.all_fields:
        try:
            v = _to_int(fld.show)
        except (TypeError, ValueError):
            continue
        if drop_grease and is_grease(v):
            continue
        out.append(v)
    return out


def compute_ja3(tls) -> tuple[str, str] | None:
    """Compute (ja3_string, ja3_md5) from a pyshark TLS layer, or None.

    The caller should ensure the layer carries a Client Hello (handshake type 1).
    """
    version = _one_int(tls, "handshake_version")
    if version is None:
        return None
    ciphers = _all_ints(tls, "handshake_ciphersuite")
    extensions = _all_ints(tls, "handshake_extension_type")
    curves = _all_ints(tls, "handshake_extensions_supported_group")
    point_formats = _all_ints(
        tls, "handshake_extensions_ec_point_format", drop_grease=False
    )
    return ja3_from_components(version, ciphers, extensions, curves, point_formats)

"""JA4 TLS client fingerprinting (FoxIO JA4+, successor to JA3).

JA4 = ``{a}_{b}_{c}`` where:
  a = protocol + tls_version + sni_flag + cipher_count + ext_count + alpn      (10 chars)
  b = sha256(sorted ciphers, hex, GREASE-removed)[:12]
  c = sha256(sorted extensions [GREASE/SNI/ALPN removed] + "_" + sig-algs in order)[:12]

Computed from the dissected Client Hello (portable across tshark versions). Modern
tshark exposes a native ``tls.handshake.ja4``; the test-suite uses it as an oracle
to validate this implementation, but ARGUS does not depend on it at runtime.
"""

from __future__ import annotations

import hashlib

from argus.ja3 import is_grease

# legacy/effective TLS version code -> JA4 2-char token
_VERSION = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
    0xFEFF: "d1",
    0xFEFD: "d2",
}

SNI_EXT = 0x0000
ALPN_EXT = 0x0010
SUPPORTED_VERSIONS_EXT = 0x002B


def _hex4(value: int) -> str:
    return f"{value:04x}"


def _sha12(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def ja4_from_components(
    protocol: str,
    version: int,
    sni_present: bool,
    ciphers: list[int],
    extensions: list[int],
    sig_algs: list[int],
    alpn_first: str | None,
) -> str:
    """Build a JA4 string from already-parsed, GREASE-filtered components."""
    ver = _VERSION.get(version, "00")
    sni = "d" if sni_present else "i"
    nc = min(len(ciphers), 99)
    ne = min(len(extensions), 99)
    if alpn_first:
        alpn = f"{alpn_first[0]}{alpn_first[-1]}"
    else:
        alpn = "00"
    a = f"{protocol}{ver}{sni}{nc:02d}{ne:02d}{alpn}"

    if ciphers:
        b = _sha12(",".join(sorted(_hex4(c) for c in ciphers)))
    else:
        b = "000000000000"

    ext_for_c = sorted(
        _hex4(e) for e in extensions if e not in (SNI_EXT, ALPN_EXT)
    )
    ext_str = ",".join(ext_for_c)
    # The "_signature_algorithms" section is appended only when present.
    if sig_algs:
        c_raw = f"{ext_str}_{','.join(_hex4(s) for s in sig_algs)}"
    else:
        c_raw = ext_str
    c = _sha12(c_raw)
    return f"{a}_{b}_{c}"


# --- pyshark extraction ---------------------------------------------------- #
def _all_ints(tls, name: str, drop_grease: bool = True) -> list[int]:
    container = tls.get_field(name)
    if container is None:
        return []
    out: list[int] = []
    for fld in container.all_fields:
        text = fld.show.strip()
        try:
            v = int(text, 16) if text.lower().startswith("0x") else int(text)
        except (TypeError, ValueError):
            continue
        if drop_grease and is_grease(v):
            continue
        out.append(v)
    return out


def _effective_version(tls, all_extensions: list[int]) -> int:
    # Prefer the highest non-GREASE version from supported_versions, else legacy.
    versions = _all_ints(tls, "handshake_extensions_supported_version")
    if versions:
        return max(versions)
    try:
        text = getattr(tls, "handshake_version")
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except (AttributeError, TypeError, ValueError):
        return 0


def _alpn_first(tls) -> str | None:
    container = tls.get_field("handshake_extensions_alpn_str")
    if container is None:
        return None
    for fld in container.all_fields:
        val = (fld.show or "").strip()
        if val:
            return val
    return None


def compute_ja4(tls, protocol: str = "t") -> str | None:
    """Compute the JA4 string from a pyshark TLS layer (Client Hello)."""
    ciphers = _all_ints(tls, "handshake_ciphersuite")
    all_ext = _all_ints(tls, "handshake_extension_type")
    if not all_ext and not ciphers:
        return None
    sig_algs = _all_ints(tls, "handshake_sig_hash_alg", drop_grease=False)
    sni_present = SNI_EXT in all_ext
    version = _effective_version(tls, all_ext)
    return ja4_from_components(
        protocol, version, sni_present, ciphers, all_ext, sig_algs, _alpn_first(tls)
    )

"""Shared helpers for rule plugins (not a Rule itself)."""

from __future__ import annotations

import math
from collections import Counter


def layer(pkt, *names):
    """Return the first matching pyshark layer, or None.

    ``pkt`` is a NormalizedPacket. Layer names vary (e.g. tshark dissects
    Netlogon as ``rpc_netlogon``), so several candidates may be tried.
    """
    raw = getattr(pkt, "raw", None)
    if raw is None:
        return None
    for name in names:
        try:
            val = getattr(raw, name)
            if val is not None:
                return val
        except AttributeError:
            continue
    return None


def field(obj, *names, default=None):
    """Safe getattr across candidate field names on a pyshark layer."""
    if obj is None:
        return default
    for n in names:
        try:
            val = getattr(obj, n)
            if val is not None:
                return val
        except AttributeError:
            continue
    return default


def truthy(value) -> bool:
    """Interpret a pyshark boolean-ish field value as a bool."""
    return value is True or str(value).lower() in ("1", "true")


def is_all_zero_hex(value: str | None) -> bool:
    """True if a hex string (with or without ':' separators) is all zeros."""
    if not value:
        return False
    stripped = value.replace(":", "").strip()
    return len(stripped) > 0 and set(stripped) == {"0"}


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string — high for random/encoded data."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

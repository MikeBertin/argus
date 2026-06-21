"""Ingest — turn a pcap into a stream of NormalizedPackets via pyshark/tshark.

pyshark layers raise ``AttributeError`` for absent fields, so every extraction
is defensive. The raw pyshark packet is attached to each NormalizedPacket for
rules that need protocol-specific dissector fields.
"""

from __future__ import annotations

import asyncio
from typing import Iterator

import pyshark

from argus.models import NormalizedPacket


def _ensure_event_loop() -> None:
    """pyshark relies on a thread-current asyncio loop, which Python 3.14 no
    longer creates implicitly. Create one if the thread has none."""
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())


def _get(obj, *names, default=None):
    for n in names:
        try:
            val = getattr(obj, n)
            if val is not None:
                return val
        except AttributeError:
            continue
    return default


def _int(value, default=None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _endpoints(pkt) -> tuple[str | None, str | None]:
    ip = _get(pkt, "ip")
    if ip is not None:
        return _get(ip, "src"), _get(ip, "dst")
    ipv6 = _get(pkt, "ipv6")
    if ipv6 is not None:
        return _get(ipv6, "src"), _get(ipv6, "dst")
    return None, None


def _ports(pkt) -> tuple[int | None, int | None]:
    tl = pkt.transport_layer  # 'TCP' / 'UDP' / None
    if not tl:
        return None, None
    layer = _get(pkt, tl.lower())
    if layer is None:
        return None, None
    return _int(_get(layer, "srcport")), _int(_get(layer, "dstport"))


def _proto(pkt) -> str:
    # Prefer the highest dissected layer; fall back to transport then 'OTHER'.
    return (pkt.highest_layer or pkt.transport_layer or "OTHER").upper()


def normalize(pkt) -> NormalizedPacket:
    src, dst = _endpoints(pkt)
    sport, dport = _ports(pkt)
    ts = float(_get(pkt, "sniff_timestamp", default=0.0) or 0.0)
    length = _int(_get(pkt, "length", default=0), default=0) or 0
    number = _int(_get(pkt, "number", default=0), default=0) or 0
    return NormalizedPacket(
        number=number,
        ts=ts,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        proto=_proto(pkt),
        length=length,
        raw=pkt,
    )


def read_pcap(path: str) -> Iterator[NormalizedPacket]:
    """Yield NormalizedPackets from a capture file. Streams (low memory)."""
    _ensure_event_loop()
    cap = pyshark.FileCapture(path, keep_packets=False)
    try:
        for pkt in cap:
            yield normalize(pkt)
    finally:
        cap.close()

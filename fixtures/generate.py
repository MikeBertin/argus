"""Generate synthetic *attack* pcaps so every rule has a positive fixture.

The real captures in ``fixtures/pcaps/`` are all benign (only zerologon.pcap is
malicious), so we craft minimal, self-contained attack traffic with scapy. Each
generated capture is the smallest thing that should trip exactly one rule while
the benign captures stay silent.

Run:  python fixtures/generate.py
Output: fixtures/pcaps/generated/{dns_tunnel,icmp_exfil,cleartext_login,beaconing}.pcap
"""

from __future__ import annotations

import base64
import os
import random

from scapy.all import (  # type: ignore
    ARP,
    DNS,
    DNSQR,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    Raw,
    wrpcap,
)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "pcaps", "generated")

VICTIM = "10.0.0.50"
RESOLVER = "10.0.0.1"
C2 = "203.0.113.66"          # TEST-NET-3, safe documentation range
WEBSERVER = "203.0.113.10"

random.seed(1472)  # deterministic fixtures


def _eth(*layers):
    return Ether(src="de:ad:be:ef:00:01", dst="de:ad:be:ef:00:02") / layers[0]


def dns_tunnel(n: int = 40) -> list:
    """High-entropy, long subdomains under one parent domain = DNS tunnelling."""
    pkts = []
    t = 1_700_000_000.0
    for i in range(n):
        blob = base64.b32encode(random.randbytes(30)).decode().strip("=").lower()
        qname = f"{blob}.tunnel.evil.example"
        p = (
            Ether(src="de:ad:be:ef:00:01", dst="de:ad:be:ef:00:02")
            / IP(src=VICTIM, dst=RESOLVER)
            / UDP(sport=40000 + i, dport=53)
            / DNS(id=i, rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
        )
        p.time = t + i * 0.05
        pkts.append(p)
    return pkts


def icmp_exfil(n: int = 25, payload_size: int = 1400) -> list:
    """ICMP echo requests carrying large high-entropy payloads = exfil."""
    pkts = []
    t = 1_700_000_100.0
    for i in range(n):
        data = random.randbytes(payload_size)
        p = (
            Ether(src="de:ad:be:ef:00:01", dst="de:ad:be:ef:00:02")
            / IP(src=VICTIM, dst=C2)
            / ICMP(type=8, id=0x1337, seq=i)
            / Raw(load=data)
        )
        p.time = t + i * 0.2
        pkts.append(p)
    return pkts


def _http_packet(src, dst, sport, payload: bytes, seq: int):
    return (
        Ether(src="de:ad:be:ef:00:01", dst="de:ad:be:ef:00:02")
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=80, flags="PA", seq=seq, ack=1)
        / Raw(load=payload)
    )


def cleartext_login() -> list:
    """HTTP POST with form creds + an HTTP Basic Authorization header."""
    t = 1_700_000_200.0

    body = b"username=admin&password=hunter2&submit=Login"
    post = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: portal.evil.example\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    basic = base64.b64encode(b"admin:hunter2").decode()
    getreq = (
        b"GET /secret HTTP/1.1\r\n"
        b"Host: portal.evil.example\r\n"
        b"Authorization: Basic " + basic.encode() + b"\r\n"
        b"\r\n"
    )

    p1 = _http_packet(VICTIM, WEBSERVER, 51000, post, seq=1)
    p1.time = t
    p2 = _http_packet(VICTIM, WEBSERVER, 51002, getreq, seq=1)
    p2.time = t + 1.0
    return [p1, p2]


def beaconing(n: int = 15, interval: float = 30.0, jitter: float = 0.4) -> list:
    """Regular low-jitter call-home connections to a single C2 = beaconing."""
    pkts = []
    t = 1_700_000_300.0
    for i in range(n):
        p = (
            Ether(src="de:ad:be:ef:00:01", dst="de:ad:be:ef:00:02")
            / IP(src=VICTIM, dst=C2)
            / TCP(sport=49000 + i, dport=443, flags="S", seq=1000 + i)
        )
        p.time = t + i * interval + random.uniform(-jitter, jitter)
        pkts.append(p)
    return pkts


def port_scan_vertical(n_ports: int = 30) -> list:
    """One source SYN-probing many ports on a single host (half-open SYN scan)."""
    pkts = []
    t = 1_700_000_400.0
    ports = list(range(20, 20 + n_ports * 3, 3))  # 20,23,26,... spread of ports
    for i, dport in enumerate(ports):
        p = (
            Ether(src="de:ad:be:ef:00:01", dst="de:ad:be:ef:00:02")
            / IP(src=C2, dst=WEBSERVER)
            / TCP(sport=55000 + i, dport=dport, flags="S", seq=1)
        )
        p.time = t + i * 0.02
        pkts.append(p)
    return pkts


def port_scan_horizontal(n_hosts: int = 30, port: int = 445) -> list:
    """One source SYN-sweeping a single port across many hosts (subnet sweep)."""
    pkts = []
    t = 1_700_000_500.0
    for i in range(n_hosts):
        dst = f"203.0.113.{i + 1}"
        p = (
            Ether(src="de:ad:be:ef:00:01", dst="de:ad:be:ef:00:02")
            / IP(src=C2, dst=dst)
            / TCP(sport=56000 + i, dport=port, flags="S", seq=1)
        )
        p.time = t + i * 0.02
        pkts.append(p)
    return pkts


def arp_spoof(n_forged: int = 12) -> list:
    """Attacker floods forged ARP replies binding the gateway IP to its own MAC."""
    pkts = []
    t = 1_700_000_600.0
    gw_ip, gw_mac = "10.0.0.1", "aa:aa:aa:00:00:01"
    victim_mac, atk_mac = "aa:bb:cc:00:00:50", "de:ad:be:ef:00:01"

    # legitimate gateway announcement (gw_ip -> gw_mac)
    p = Ether(src=gw_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, psrc=gw_ip, hwsrc=gw_mac, pdst=VICTIM, hwdst=victim_mac
    )
    p.time = t
    pkts.append(p)

    # victim asks who-has the gateway
    p = Ether(src=victim_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc=VICTIM, hwsrc=victim_mac, pdst=gw_ip, hwdst="00:00:00:00:00:00"
    )
    p.time = t + 0.5
    pkts.append(p)

    # attacker poisons the binding (gw_ip -> attacker MAC), repeatedly
    for i in range(n_forged):
        p = Ether(src=atk_mac, dst=victim_mac) / ARP(
            op=2, psrc=gw_ip, hwsrc=atk_mac, pdst=VICTIM, hwdst=victim_mac
        )
        p.time = t + 1 + i * 0.5
        pkts.append(p)
    return pkts


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    captures = {
        "dns_tunnel.pcap": dns_tunnel(),
        "icmp_exfil.pcap": icmp_exfil(),
        "cleartext_login.pcap": cleartext_login(),
        "beaconing.pcap": beaconing(),
        "port_scan_vertical.pcap": port_scan_vertical(),
        "port_scan_horizontal.pcap": port_scan_horizontal(),
        "arp_spoof.pcap": arp_spoof(),
    }
    for name, pkts in captures.items():
        path = os.path.join(OUT, name)
        wrpcap(path, pkts)
        print(f"wrote {path}  ({len(pkts)} packets)")


if __name__ == "__main__":
    main()

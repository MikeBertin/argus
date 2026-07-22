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
import struct

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
from scapy.all import DNSRR  # type: ignore
from scapy.layers.dhcp import BOOTP, DHCP  # type: ignore
from scapy.layers.tls.handshake import TLSClientHello  # type: ignore
from scapy.layers.tls.extensions import (  # type: ignore
    TLS_Ext_SignatureAlgorithms,
    TLS_Ext_SupportedGroups,
    TLS_Ext_SupportedPointFormat,
)
from scapy.layers.tls.record import TLS  # type: ignore
from scapy.layers.kerberos import (  # type: ignore
    KRB_KDC_REQ_BODY,
    KRB_TGS_REQ,
    PrincipalName,
)
from scapy.asn1.asn1 import ASN1_GENERAL_STRING, ASN1_INTEGER  # type: ignore
from scapy.layers.netbios import NBTSession  # type: ignore
from scapy.layers.smb2 import (  # type: ignore
    SMB2_Header,
    SMB2_Tree_Connect_Request,
    SMB2_Tree_Connect_Response,
    SMB2_Create_Request,
    SMB2_Create_Response,
    SMB2_Write_Request,
)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "pcaps", "generated")

VICTIM = "10.0.0.50"
RESOLVER = "10.0.0.1"
C2 = "203.0.113.66"          # TEST-NET-3, safe documentation range
WEBSERVER = "203.0.113.10"
ATTACKER = "10.0.0.66"       # domain-joined foothold (kerberoasting)
DC = "10.0.0.10"             # domain controller / KDC

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


def _bruteforce(port: int, t0: float, n: int = 15) -> list:
    """One source making N full TCP login connections to one auth-service port.

    Each connection = SYN, SYN-ACK, a data segment (the auth attempt), RST — i.e.
    established + data, so it reads as a login attempt (not a scan).
    """
    pkts = []
    atk, atk_mac = C2, "de:ad:be:ef:00:01"
    target, target_mac = "10.0.0.10", "aa:bb:cc:00:00:10"
    for i in range(n):
        sport = 40000 + i
        base = t0 + i * 0.3
        syn = (
            Ether(src=atk_mac, dst=target_mac)
            / IP(src=atk, dst=target)
            / TCP(sport=sport, dport=port, flags="S", seq=1000 + i)
        )
        synack = (
            Ether(src=target_mac, dst=atk_mac)
            / IP(src=target, dst=atk)
            / TCP(sport=port, dport=sport, flags="SA", seq=5000 + i, ack=1001 + i)
        )
        data = (
            Ether(src=atk_mac, dst=target_mac)
            / IP(src=atk, dst=target)
            / TCP(sport=sport, dport=port, flags="PA", seq=1001 + i, ack=5001 + i)
            / Raw(load=b"\x00\x00login=admin pass=guess%d" % i)
        )
        rst = (
            Ether(src=atk_mac, dst=target_mac)
            / IP(src=atk, dst=target)
            / TCP(sport=sport, dport=port, flags="R", seq=1040 + i)
        )
        for j, p in enumerate((syn, synack, data, rst)):
            p.time = base + j * 0.01
            pkts.append(p)
    return pkts


def bruteforce_smb() -> list:
    return _bruteforce(445, t0=1_700_000_700.0)


def bruteforce_rdp() -> list:
    return _bruteforce(3389, t0=1_700_000_800.0)


def _client_hello(src, dst, sport, ciphers, groups, t):
    ch = TLSClientHello(
        version=0x0303,
        ciphers=ciphers,
        ext=[
            TLS_Ext_SupportedGroups(groups=groups),
            TLS_Ext_SupportedPointFormat(ecpl=["uncompressed"]),
            TLS_Ext_SignatureAlgorithms(),
        ],
    )
    p = (
        Ether(src="de:ad:be:ef:00:01", dst="de:ad:be:ef:00:02")
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=443, flags="PA", seq=1)
        / TLS(msg=[ch])
    )
    p.time = t
    return p


def _server_hello(src, dst, sport, cipher, ext_list, t):
    """Hand-crafted TLS Server Hello record (scapy's stateful TLS won't serialise
    a standalone Server Hello, so build the wire bytes directly)."""
    exts = b"".join(struct.pack(">HH", et, len(ed)) + ed for et, ed in ext_list)
    body = (
        struct.pack(">H", 0x0303) + (b"\xAA" * 32) + b"\x00"
        + struct.pack(">H", cipher) + b"\x00"
        + struct.pack(">H", len(exts)) + exts
    )
    hs = b"\x02" + struct.pack(">I", len(body))[1:] + body
    record = b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs
    p = (
        Ether(src="de:ad:be:ef:00:02", dst="de:ad:be:ef:00:01")
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=443, flags="PA", seq=1)
        / Raw(load=record)
    )
    p.time = t
    return p


def tls_fingerprint() -> list:
    """TLS Client Hellos (JA3/JA4) + Server Hellos (JA4S): a 'malicious' client and
    a 'malicious' server (both blocklisted by the seed), plus benign counterparts
    (enrichment only)."""
    t = 1_700_000_900.0
    mal_client = _client_hello(
        VICTIM, C2, 51000,
        ciphers=[0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x002F, 0x0035],
        groups=["x25519", "secp256r1", "secp384r1"], t=t,
    )
    benign_client = _client_hello(
        VICTIM, "93.184.216.34", 51002,
        ciphers=[0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0x009E],
        groups=["x25519", "secp256r1"], t=t + 1,
    )
    # malicious C2 server: TLS 1.2, distinctive extension set → seeded JA4S
    mal_server = _server_hello(
        C2, VICTIM, 443, 0xC02B,
        [(0xFF01, b"\x00"), (0x000B, b"\x02\x01\x00"), (0x0023, b"")], t=t + 2,
    )
    # benign server: TLS 1.3 (supported_versions + key_share)
    benign_server = _server_hello(
        "93.184.216.34", VICTIM, 443, 0x1301,
        [(0x002B, b"\x03\x04"), (0x0033, b"\x00\x1d\x00\x20" + b"\xBB" * 32)], t=t + 3,
    )
    return [mal_client, benign_client, mal_server, benign_server]


def llmnr_spoof(n_names: int = 6) -> list:
    """A poisoner answering LLMNR queries for many distinct names (Responder)."""
    pkts = []
    t = 1_700_001_000.0
    attacker = "10.0.0.66"
    names = ["wpad", "fileserver", "intranet", "printsrv", "backup", "sharepoint"][:n_names]
    for i, name in enumerate(names):
        # LLMNR uses the DNS wire format on UDP 5355; response → attacker IP.
        p = (
            Ether(src="de:ad:be:ef:00:01", dst="de:ad:be:ef:00:02")
            / IP(src=attacker, dst=VICTIM)
            / UDP(sport=5355, dport=50000 + i)
            / DNS(id=i, qr=1, qd=DNSQR(qname=name, qtype="A"),
                  an=DNSRR(rrname=name, type="A", rdata=attacker))
        )
        p.time = t + i * 0.1
        pkts.append(p)
    return pkts


def _tgs_req(src, spn: str, etypes: list[int], t: float, cname: str):
    """A Kerberos TGS-REQ (msg-type 12) for one SPN, offering `etypes`."""
    sname = PrincipalName(
        nameType=ASN1_INTEGER(2),  # kRB5-NT-SRV-INST
        nameString=[ASN1_GENERAL_STRING(p.encode()) for p in spn.split("/")],
    )
    principal = PrincipalName(
        nameType=ASN1_INTEGER(1),  # kRB5-NT-PRINCIPAL
        nameString=[ASN1_GENERAL_STRING(cname.encode())],
    )
    body = KRB_KDC_REQ_BODY(
        cname=principal,
        realm=ASN1_GENERAL_STRING(b"CORP.LOCAL"),
        sname=sname,
        nonce=ASN1_INTEGER(0x1234),
        etype=[ASN1_INTEGER(e) for e in etypes],
    )
    p = (
        Ether(src="de:ad:be:ef:00:01", dst="aa:aa:aa:00:00:10")
        / IP(src=src, dst=DC)
        / UDP(sport=45000, dport=88)
        / KRB_TGS_REQ(reqBody=body)
    )
    p.time = t
    return p


# SPNs of the kind roasting tools target: service accounts, not machine accounts.
ROAST_SPNS = [
    "MSSQLSvc/db01.corp.local:1433",
    "MSSQLSvc/db02.corp.local:1433",
    "HTTP/intranet.corp.local",
    "HTTP/reports.corp.local",
    "CIFS/fileserver.corp.local",
    "FTP/archive.corp.local",
    "LDAP/app01.corp.local",
    "TERMSRV/jump01.corp.local",
]


def kerberoasting(n_spns: int = 8) -> list:
    """One client sweeping many SPNs and requesting RC4 (etype 23) — crackable."""
    t = 1_700_001_200.0
    return [
        _tgs_req(ATTACKER, spn, [23], t + i * 0.3, "attacker")
        for i, spn in enumerate(ROAST_SPNS[:n_spns])
    ]


def kerberos_benign(n_spns: int = 6) -> list:
    """FP guard: a normal workstation requesting service tickets with AES.

    Same *shape* as the attack (one client, several distinct SPNs) but modern
    encryption — so only the weak-etype half of the signal is missing. This is
    what stops the rule degenerating into "alert on any burst of TGS-REQs".
    """
    t = 1_700_001_300.0
    spns = [
        "CIFS/fileserver.corp.local",
        "LDAP/dc01.corp.local",
        "HOST/dc01.corp.local",
        "HTTP/intranet.corp.local",
        "CIFS/printsrv.corp.local",
        "HOST/app01.corp.local",
    ][:n_spns]
    pkts = [
        _tgs_req(VICTIM, spn, [18, 17], t + i * 2.0, "alice")
        for i, spn in enumerate(spns)
    ]
    # A krbtgt referral is routine and must be ignored, even with RC4 offered.
    pkts.append(_tgs_req(VICTIM, "krbtgt/CORP.LOCAL", [23], t + 20.0, "alice"))
    return pkts


def _smb_session(src, dst, share: str, filename: str, t: float) -> list:
    """A minimal SMB2 exchange: TreeConnect(share) -> Create(file) -> Write.

    scapy handles the UTF-16 buffer encoding, and tshark binds the TID to the
    share name across the session so the tree resolves on the create/write.
    """
    seq = {"c": 1000, "s": 5000}

    def frame(payload, to_server, ts):
        if to_server:
            ip = IP(src=src, dst=dst)
            tcp = TCP(sport=50100, dport=445, flags="PA", seq=seq["c"], ack=seq["s"])
            seq["c"] += len(bytes(payload)) + 4
        else:
            ip = IP(src=dst, dst=src)
            tcp = TCP(sport=445, dport=50100, flags="PA", seq=seq["s"], ack=seq["c"])
            seq["s"] += len(bytes(payload)) + 4
        p = (Ether(src="de:ad:be:ef:00:01", dst="aa:aa:aa:00:00:20")
             / ip / tcp / NBTSession() / payload)
        p.time = ts
        return p

    sid, tid = 0x99, 5
    pkts = [
        frame(SMB2_Header(Command=3, MID=1, SessionId=sid, TID=0)
              / SMB2_Tree_Connect_Request(Buffer=[("Path", share)]), True, t),
        frame(SMB2_Header(Command=3, MID=1, SessionId=sid, TID=tid, Flags=1)
              / SMB2_Tree_Connect_Response(ShareType=1), False, t + 0.01),
        frame(SMB2_Header(Command=5, MID=2, SessionId=sid, TID=tid)
              / SMB2_Create_Request(Buffer=[("Name", filename)]), True, t + 0.02),
        frame(SMB2_Header(Command=5, MID=2, SessionId=sid, TID=tid, Flags=1)
              / SMB2_Create_Response(), False, t + 0.03),
        frame(SMB2_Header(Command=9, MID=3, SessionId=sid, TID=tid)
              / SMB2_Write_Request(Data=b"MZ\x90\x00" + b"\x00" * 128), True, t + 0.04),
    ]
    return pkts


def smb_lateral() -> list:
    """PsExec-style drop: an executable written to the victim's ADMIN$ share."""
    return _smb_session(ATTACKER, "10.0.0.20", "\\\\SRV01\\ADMIN$",
                        "PSEXESVC.exe", 1_700_001_400.0)


def smb_benign() -> list:
    """FP guard: a normal file copy to an ordinary (non-admin) file share.

    Same SMB2 machinery as the attack, but a regular share and a document —
    proving the rule keys on admin-disk-share + executable, not on SMB writes
    in general. (zerologon.pcap is the other guard: real IPC$/svcctl RPC.)"""
    return _smb_session(VICTIM, "10.0.0.20", "\\\\SRV01\\Shared",
                        "quarterly_report.docx", 1_700_001_500.0)


def _dhcp_offer(server_ip, server_mac, gateway, dns, t):
    return (
        Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=server_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr="10.0.0.123", siaddr=server_ip)
        / DHCP(options=[
            ("message-type", "offer"),
            ("server_id", server_ip),
            ("router", gateway),
            ("name_server", dns),
            "end",
        ])
    )


def rogue_dhcp() -> list:
    """Legit DHCP offer (gateway .1) racing a rogue offer (gateway = attacker)."""
    t = 1_700_001_100.0
    legit = _dhcp_offer("10.0.0.1", "aa:aa:aa:00:00:01", "10.0.0.1", "10.0.0.1", t)
    rogue = _dhcp_offer("10.0.0.66", "de:ad:be:ef:00:01", "10.0.0.66", "10.0.0.66", t + 0.2)
    legit.time, rogue.time = t, t + 0.2
    return [legit, rogue]


def _dns_over_tcp(src, dst, sport, dport, dns_obj, t):
    """One DNS message over TCP/53, with the mandatory 2-byte length prefix."""
    raw = bytes(dns_obj)
    p = (
        Ether(src="de:ad:be:ef:00:01", dst="de:ad:be:ef:00:02")
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, flags="PA", seq=1)
        / Raw(struct.pack("!H", len(raw)) + raw)
    )
    p.time = t
    return p


def dns_zone_transfer() -> list:
    """AXFR request + a successful response dumping the whole zone (HIGH tier)."""
    t = 1_700_001_600.0
    zone = "corp.local"
    req = DNS(id=7, rd=0, qd=DNSQR(qname=zone, qtype="AXFR"))
    # A successful transfer: SOA + several host records handed back.
    rrs = (
        DNSRR(rrname=zone, type="SOA", rdata="ns1.corp.local")
        / DNSRR(rrname="dc01.corp.local", type="A", rdata="10.0.0.10")
        / DNSRR(rrname="www.corp.local", type="A", rdata="10.0.0.20")
        / DNSRR(rrname="mail.corp.local", type="A", rdata="10.0.0.25")
        / DNSRR(rrname="vpn.corp.local", type="A", rdata="10.0.0.30")
    )
    resp = DNS(id=7, qr=1, aa=1, ancount=5, qd=DNSQR(qname=zone, qtype="AXFR"), an=rrs)
    return [
        _dns_over_tcp(ATTACKER, DC, 51000, 53, req, t),
        _dns_over_tcp(DC, ATTACKER, 53, 51000, resp, t + 0.2),
    ]


def dns_over_tcp_benign() -> list:
    """FP guard: an ordinary A lookup over TCP/53 (large/DNSSEC responses use
    TCP too). Proves dns_zone_transfer keys on the AXFR *qtype*, not on the
    transport — normal DNS-over-TCP must stay silent."""
    t = 1_700_001_700.0
    q = DNS(id=8, rd=1, qd=DNSQR(qname="www.corp.local", qtype="A"))
    a = DNS(id=8, qr=1, ancount=1, qd=DNSQR(qname="www.corp.local", qtype="A"),
            an=DNSRR(rrname="www.corp.local", type="A", rdata="10.0.0.20"))
    return [
        _dns_over_tcp(VICTIM, RESOLVER, 52000, 53, q, t),
        _dns_over_tcp(RESOLVER, VICTIM, 53, 52000, a, t + 0.1),
    ]


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
        "bruteforce_smb.pcap": bruteforce_smb(),
        "bruteforce_rdp.pcap": bruteforce_rdp(),
        "tls_fingerprint.pcap": tls_fingerprint(),
        "llmnr_spoof.pcap": llmnr_spoof(),
        "rogue_dhcp.pcap": rogue_dhcp(),
        "kerberoasting.pcap": kerberoasting(),
        "kerberos_benign.pcap": kerberos_benign(),
        "smb_lateral.pcap": smb_lateral(),
        "smb_benign.pcap": smb_benign(),
        "dns_zone_transfer.pcap": dns_zone_transfer(),
        "dns_over_tcp_benign.pcap": dns_over_tcp_benign(),
    }
    for name, pkts in captures.items():
        path = os.path.join(OUT, name)
        wrpcap(path, pkts)
        print(f"wrote {path}  ({len(pkts)} packets)")


if __name__ == "__main__":
    main()

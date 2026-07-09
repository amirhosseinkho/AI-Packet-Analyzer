from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class ParsedPacket(BaseModel):
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    length: int
    ttl: Optional[int] = None
    tcp_flags: Optional[str] = None
    payload_preview: Optional[str] = None

    # DNS
    dns_query: Optional[str] = None
    dns_response: Optional[str] = None

    # HTTP
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_path: Optional[str] = None

    # ARP
    arp_op: Optional[str] = None
    arp_hwsrc: Optional[str] = None
    arp_hwdst: Optional[str] = None

    inter_arrival_time: Optional[float] = None
    flow_id: Optional[str] = None

    def compute_flow_id(self) -> str:
        """Bidirectional flow key."""
        five_tuple = tuple(
            sorted(
                [
                    f"{self.src_ip}:{self.src_port or 0}",
                    f"{self.dst_ip}:{self.dst_port or 0}",
                ]
            )
        ) + (self.protocol,)
        return hashlib.md5("|".join(five_tuple).encode()).hexdigest()


_TCP_FLAG_BITS: dict[str, int] = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
    "ECE": 0x40,
    "CWR": 0x80,
}


def _decode_tcp_flags(flags_int: int) -> str:
    return "".join(name for name, bit in _TCP_FLAG_BITS.items() if flags_int & bit)


def parse_scapy_packet(scapy_pkt: Any) -> Optional[ParsedPacket]:
    """Convert a raw Scapy packet into a structured ParsedPacket.

    Returns None for packets that cannot be parsed into a supported protocol.
    """
    try:
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.l2 import ARP, Ether
    except ImportError:
        return None

    if not scapy_pkt.haslayer(IP) and not scapy_pkt.haslayer(ARP):
        return None

    ts = datetime.fromtimestamp(float(scapy_pkt.time), tz=timezone.utc)
    length = len(scapy_pkt)

    # ── ARP ──────────────────────────────────────────────────────────────────
    if scapy_pkt.haslayer(ARP):
        arp = scapy_pkt[ARP]
        pkt = ParsedPacket(
            timestamp=ts,
            src_ip=arp.psrc,
            dst_ip=arp.pdst,
            protocol="ARP",
            length=length,
            arp_op="request" if arp.op == 1 else "reply",
            arp_hwsrc=arp.hwsrc,
            arp_hwdst=arp.hwdst,
        )
        pkt.flow_id = pkt.compute_flow_id()
        return pkt

    ip = scapy_pkt[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    ttl = ip.ttl
    protocol = "OTHER"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    dns_query: Optional[str] = None
    dns_response: Optional[str] = None
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_path: Optional[str] = None
    payload_preview: Optional[str] = None

    # ── TCP ───────────────────────────────────────────────────────────────────
    if scapy_pkt.haslayer(TCP):
        tcp = scapy_pkt[TCP]
        protocol = "TCP"
        src_port = tcp.sport
        dst_port = tcp.dport
        tcp_flags = _decode_tcp_flags(int(tcp.flags))

        # HTTP detection (port 80 / 8080)
        if scapy_pkt.haslayer(HTTPRequest):
            req = scapy_pkt[HTTPRequest]
            protocol = "HTTP"
            http_method = req.Method.decode(errors="replace") if req.Method else None
            http_host = req.Host.decode(errors="replace") if req.Host else None
            http_path = req.Path.decode(errors="replace") if req.Path else None
        elif dst_port == 443 or src_port == 443:
            protocol = "HTTPS"

        raw = bytes(tcp.payload)
        if raw:
            payload_preview = raw[:64].hex()

    # ── UDP ───────────────────────────────────────────────────────────────────
    elif scapy_pkt.haslayer(UDP):
        udp = scapy_pkt[UDP]
        protocol = "UDP"
        src_port = udp.sport
        dst_port = udp.dport

        if scapy_pkt.haslayer(DNS):
            dns = scapy_pkt[DNS]
            protocol = "DNS"
            if dns.qd:
                dns_query = dns.qd.qname.decode(errors="replace").rstrip(".")
            if dns.an:
                rrs: list[str] = []
                rr = dns.an
                while rr:
                    if hasattr(rr, "rdata"):
                        rrs.append(str(rr.rdata))
                    rr = rr.payload if hasattr(rr, "payload") else None
                dns_response = ",".join(rrs)

    # ── ICMP ──────────────────────────────────────────────────────────────────
    elif scapy_pkt.haslayer(ICMP):
        protocol = "ICMP"

    pkt = ParsedPacket(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        ttl=ttl,
        tcp_flags=tcp_flags,
        payload_preview=payload_preview,
        dns_query=dns_query,
        dns_response=dns_response,
        http_method=http_method,
        http_host=http_host,
        http_path=http_path,
    )
    pkt.flow_id = pkt.compute_flow_id()
    return pkt

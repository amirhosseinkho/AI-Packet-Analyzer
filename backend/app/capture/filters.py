from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CaptureFilter:
    """BPF-compatible capture filter builder."""

    protocols: list[str] = field(default_factory=list)  # tcp, udp, icmp, arp
    src_ips: list[str] = field(default_factory=list)
    dst_ips: list[str] = field(default_factory=list)
    src_ports: list[int] = field(default_factory=list)
    dst_ports: list[int] = field(default_factory=list)
    raw_bpf: Optional[str] = None

    def to_bpf(self) -> str:
        if self.raw_bpf:
            return self.raw_bpf

        parts: list[str] = []

        if self.protocols:
            proto_expr = " or ".join(self.protocols)
            parts.append(f"({proto_expr})")

        if self.src_ips:
            ip_expr = " or ".join(f"src host {ip}" for ip in self.src_ips)
            parts.append(f"({ip_expr})")

        if self.dst_ips:
            ip_expr = " or ".join(f"dst host {ip}" for ip in self.dst_ips)
            parts.append(f"({ip_expr})")

        if self.src_ports:
            port_expr = " or ".join(f"src port {p}" for p in self.src_ports)
            parts.append(f"({port_expr})")

        if self.dst_ports:
            port_expr = " or ".join(f"dst port {p}" for p in self.dst_ports)
            parts.append(f"({port_expr})")

        return " and ".join(parts) if parts else ""

    @classmethod
    def default(cls) -> "CaptureFilter":
        return cls(protocols=["tcp", "udp", "icmp", "arp"])

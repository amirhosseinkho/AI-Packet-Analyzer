from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from app.capture.parser import ParsedPacket


class FlowStatistics(BaseModel):
    """Mutable statistics object accumulated from packets in a flow."""

    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str

    start_time: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    end_time: Optional[datetime] = None
    last_seen: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    duration_seconds: Optional[float] = None

    packet_count: int = 0
    byte_count: int = 0
    avg_packet_size: Optional[float] = None
    min_packet_size: Optional[int] = None
    max_packet_size: Optional[int] = None

    # TCP flags
    tcp_syn_count: int = 0
    tcp_fin_count: int = 0
    tcp_rst_count: int = 0
    tcp_ack_count: int = 0
    tcp_psh_count: int = 0

    # Rate features (set by finalise())
    packets_per_second: Optional[float] = None
    bytes_per_second: Optional[float] = None

    is_finalised: bool = False

    model_config = {"arbitrary_types_allowed": True}

    def add_packet(self, pkt: ParsedPacket) -> None:
        self.packet_count += 1
        self.byte_count += pkt.length
        self.last_seen = datetime.now(tz=timezone.utc)

        if self.min_packet_size is None or pkt.length < self.min_packet_size:
            self.min_packet_size = pkt.length
        if self.max_packet_size is None or pkt.length > self.max_packet_size:
            self.max_packet_size = pkt.length

        if pkt.tcp_flags:
            flags = pkt.tcp_flags.upper()
            if "SYN" in flags:
                self.tcp_syn_count += 1
            if "FIN" in flags:
                self.tcp_fin_count += 1
            if "RST" in flags:
                self.tcp_rst_count += 1
            if "ACK" in flags:
                self.tcp_ack_count += 1
            if "PSH" in flags:
                self.tcp_psh_count += 1

    def finalise(self) -> None:
        self.is_finalised = True
        self.end_time = datetime.now(tz=timezone.utc)
        self.duration_seconds = (self.end_time - self.start_time).total_seconds()
        if self.packet_count > 0:
            self.avg_packet_size = self.byte_count / self.packet_count
        if self.duration_seconds and self.duration_seconds > 0:
            self.packets_per_second = self.packet_count / self.duration_seconds
            self.bytes_per_second = self.byte_count / self.duration_seconds

    def to_feature_vector(self) -> list[float]:
        """Numeric feature vector for ML models."""
        return [
            float(self.packet_count),
            float(self.byte_count),
            float(self.avg_packet_size or 0),
            float(self.duration_seconds or 0),
            float(self.packets_per_second or 0),
            float(self.bytes_per_second or 0),
            float(self.tcp_syn_count),
            float(self.tcp_fin_count),
            float(self.tcp_rst_count),
            float(self.tcp_ack_count),
            float(self.tcp_psh_count),
            float(self.src_port or 0),
            float(self.dst_port or 0),
        ]

    @property
    def feature_names(self) -> list[str]:
        return [
            "packet_count", "byte_count", "avg_packet_size",
            "duration_seconds", "packets_per_second", "bytes_per_second",
            "tcp_syn_count", "tcp_fin_count", "tcp_rst_count",
            "tcp_ack_count", "tcp_psh_count", "src_port", "dst_port",
        ]

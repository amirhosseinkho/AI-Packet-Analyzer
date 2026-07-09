from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base


class Packet(Base):
    __tablename__ = "packets"
    __table_args__ = (
        Index("ix_packets_timestamp", "timestamp"),
        Index("ix_packets_src_ip", "src_ip"),
        Index("ix_packets_dst_ip", "dst_ip"),
        Index("ix_packets_protocol", "protocol"),
        Index("ix_packets_flow_id", "flow_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    length: Mapped[int] = mapped_column(Integer, nullable=False)
    ttl: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    tcp_flags: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    payload_preview: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    flow_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # DNS fields
    dns_query: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    dns_response: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # HTTP fields
    http_method: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    http_host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    http_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ARP fields
    arp_op: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    arp_hwsrc: Mapped[Optional[str]] = mapped_column(String(17), nullable=True)
    arp_hwdst: Mapped[Optional[str]] = mapped_column(String(17), nullable=True)

    inter_arrival_time: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    def __repr__(self) -> str:
        return f"<Packet {self.id} {self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port} [{self.protocol}]>"

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, DateTime, Float, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base


class Flow(Base):
    __tablename__ = "flows"
    __table_args__ = (
        Index("ix_flows_flow_id", "flow_id", unique=True),
        Index("ix_flows_start_time", "start_time"),
        Index("ix_flows_protocol", "protocol"),
        Index("ix_flows_src_ip", "src_ip"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    flow_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)

    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)

    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    packet_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    byte_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    avg_packet_size: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    min_packet_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    max_packet_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # TCP flag statistics
    tcp_syn_count: Mapped[int] = mapped_column(Integer, default=0)
    tcp_fin_count: Mapped[int] = mapped_column(Integer, default=0)
    tcp_rst_count: Mapped[int] = mapped_column(Integer, default=0)
    tcp_ack_count: Mapped[int] = mapped_column(Integer, default=0)
    tcp_psh_count: Mapped[int] = mapped_column(Integer, default=0)

    # Rate features
    packets_per_second: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    bytes_per_second: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def __repr__(self) -> str:
        return f"<Flow {self.flow_id} pkts={self.packet_count} bytes={self.byte_count}>"

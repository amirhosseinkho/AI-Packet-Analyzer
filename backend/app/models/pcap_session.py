from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base


class PcapSession(Base):
    """Persistent metadata record for a PCAP chat session.

    The heavy in-memory state (RAG index, chat history) lives in the
    SessionStore; this table provides audit trail and restorability hints.
    """

    __tablename__ = "pcap_sessions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    total_packets: Mapped[int] = mapped_column(Integer, default=0)
    total_flows: Mapped[int] = mapped_column(Integer, default=0)
    total_anomalies: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    chunk_count: Mapped[int] = mapped_column(Integer, default=0)
    message_count: Mapped[int] = mapped_column(Integer, default=0)
    llm_provider: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_active_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<PcapSession {self.session_id} file={self.filename}>"

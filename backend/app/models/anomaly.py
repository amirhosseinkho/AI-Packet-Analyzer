from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base


class Anomaly(Base):
    __tablename__ = "anomalies"
    __table_args__ = (
        Index("ix_anomalies_flow_id", "flow_id"),
        Index("ix_anomalies_detected_at", "detected_at"),
        Index("ix_anomalies_anomaly_type", "anomaly_type"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    flow_id: Mapped[str] = mapped_column(String(128), nullable=False)

    detector_name: Mapped[str] = mapped_column(String(64), nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    is_anomaly: Mapped[bool] = mapped_column(default=False)
    anomaly_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Combined score from ensemble
    ensemble_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # LLM explanation
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)  # low / medium / high / critical

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Anomaly flow={self.flow_id} score={self.anomaly_score:.3f} is_anomaly={self.is_anomaly}>"

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import distinct, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import ProtocolStats, TrafficStats
from app.database import get_db
from app.models.anomaly import Anomaly
from app.models.flow import Flow
from app.models.packet import Packet

router = APIRouter(prefix="/statistics", tags=["statistics"])


@router.get("", response_model=TrafficStats)
async def get_statistics(db: AsyncSession = Depends(get_db)) -> TrafficStats:
    total_packets = (await db.execute(select(func.count()).select_from(Packet))).scalar_one()
    total_bytes = (await db.execute(select(func.coalesce(func.sum(Packet.length), 0)))).scalar_one()
    total_flows = (await db.execute(select(func.count()).select_from(Flow))).scalar_one()
    total_anomalies = (
        await db.execute(select(func.count()).select_from(Anomaly).where(Anomaly.is_anomaly.is_(True)))
    ).scalar_one()

    anomaly_rate = (total_anomalies / total_flows * 100) if total_flows else 0.0

    # Protocol breakdown
    proto_rows = (
        await db.execute(
            select(Packet.protocol, func.count().label("cnt"), func.sum(Packet.length).label("bytes"))
            .group_by(Packet.protocol)
            .order_by(func.count().desc())
        )
    ).all()

    proto_stats: list[ProtocolStats] = []
    for row in proto_rows:
        pct = (row.cnt / total_packets * 100) if total_packets else 0.0
        proto_stats.append(
            ProtocolStats(protocol=row.protocol, count=row.cnt, bytes=row.bytes or 0, pct=round(pct, 2))
        )

    # Top talkers (src_ip)
    talker_rows = (
        await db.execute(
            select(Packet.src_ip, func.count().label("cnt"), func.sum(Packet.length).label("bytes"))
            .group_by(Packet.src_ip)
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()

    top_talkers = [{"ip": r.src_ip, "packets": r.cnt, "bytes": r.bytes or 0} for r in talker_rows]

    # Capture duration from first / last packet timestamps
    ts_range = (
        await db.execute(select(func.min(Packet.timestamp), func.max(Packet.timestamp)))
    ).one()
    capture_duration: float | None = None
    if ts_range[0] and ts_range[1]:
        capture_duration = (ts_range[1] - ts_range[0]).total_seconds()

    return TrafficStats(
        total_packets=total_packets,
        total_bytes=total_bytes,
        total_flows=total_flows,
        total_anomalies=total_anomalies,
        anomaly_rate=round(anomaly_rate, 2),
        protocol_breakdown=proto_stats,
        top_talkers=top_talkers,
        capture_duration_seconds=capture_duration,
    )

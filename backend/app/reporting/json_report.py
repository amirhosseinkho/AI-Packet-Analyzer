from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anomaly import Anomaly
from app.models.flow import Flow
from app.models.packet import Packet


async def generate_json_report(
    db: AsyncSession,
    output_path: Path,
    period_start: Optional[datetime] = None,
    period_end: Optional[datetime] = None,
) -> dict:
    pkt_stmt = select(Packet)
    flow_stmt = select(Flow)
    anomaly_stmt = select(Anomaly).where(Anomaly.is_anomaly.is_(True))

    if period_start:
        pkt_stmt = pkt_stmt.where(Packet.timestamp >= period_start)
        flow_stmt = flow_stmt.where(Flow.start_time >= period_start)
        anomaly_stmt = anomaly_stmt.where(Anomaly.detected_at >= period_start)
    if period_end:
        pkt_stmt = pkt_stmt.where(Packet.timestamp <= period_end)
        flow_stmt = flow_stmt.where(Flow.start_time <= period_end)
        anomaly_stmt = anomaly_stmt.where(Anomaly.detected_at <= period_end)

    packets = (await db.execute(pkt_stmt.limit(10_000))).scalars().all()
    flows = (await db.execute(flow_stmt)).scalars().all()
    anomalies = (await db.execute(anomaly_stmt)).scalars().all()

    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "period": {
            "start": period_start.isoformat() if period_start else None,
            "end": period_end.isoformat() if period_end else None,
        },
        "summary": {
            "packet_count": len(packets),
            "flow_count": len(flows),
            "anomaly_count": len(anomalies),
        },
        "anomalies": [
            {
                "flow_id": a.flow_id,
                "type": a.anomaly_type,
                "severity": a.severity,
                "score": a.ensemble_score,
                "explanation": a.explanation,
                "detected_at": a.detected_at.isoformat(),
            }
            for a in anomalies
        ],
        "protocol_breakdown": _protocol_breakdown(packets),
        "top_talkers": _top_talkers(packets),
    }

    output_path.write_text(json.dumps(report, indent=2, default=str))
    return report


def _protocol_breakdown(packets: list) -> dict:
    breakdown: dict[str, int] = {}
    for p in packets:
        breakdown[p.protocol] = breakdown.get(p.protocol, 0) + 1
    return breakdown


def _top_talkers(packets: list) -> list:
    counts: dict[str, int] = {}
    for p in packets:
        counts[p.src_ip] = counts.get(p.src_ip, 0) + 1
    return sorted([{"ip": ip, "packets": n} for ip, n in counts.items()], key=lambda x: -x["packets"])[:10]

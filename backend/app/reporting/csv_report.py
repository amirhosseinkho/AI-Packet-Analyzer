from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anomaly import Anomaly
from app.models.flow import Flow


async def generate_csv_report(
    db: AsyncSession,
    output_path: Path,
    period_start: Optional[datetime] = None,
    period_end: Optional[datetime] = None,
) -> dict:
    flow_stmt = select(Flow)
    anomaly_stmt = select(Anomaly)

    if period_start:
        flow_stmt = flow_stmt.where(Flow.start_time >= period_start)
        anomaly_stmt = anomaly_stmt.where(Anomaly.detected_at >= period_start)
    if period_end:
        flow_stmt = flow_stmt.where(Flow.start_time <= period_end)
        anomaly_stmt = anomaly_stmt.where(Anomaly.detected_at <= period_end)

    flows = (await db.execute(flow_stmt)).scalars().all()
    anomalies = (await db.execute(anomaly_stmt)).scalars().all()
    anomaly_map = {a.flow_id: a for a in anomalies}

    flow_fields = [
        "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "start_time", "duration_seconds", "packet_count", "byte_count",
        "avg_packet_size", "packets_per_second", "bytes_per_second",
        "tcp_syn_count", "tcp_rst_count", "is_anomaly", "anomaly_type",
        "anomaly_score", "severity", "explanation",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=flow_fields)
        writer.writeheader()
        for flow in flows:
            anomaly = anomaly_map.get(flow.flow_id)
            writer.writerow(
                {
                    "flow_id": flow.flow_id,
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "src_port": flow.src_port,
                    "dst_port": flow.dst_port,
                    "protocol": flow.protocol,
                    "start_time": flow.start_time.isoformat() if flow.start_time else "",
                    "duration_seconds": flow.duration_seconds,
                    "packet_count": flow.packet_count,
                    "byte_count": flow.byte_count,
                    "avg_packet_size": flow.avg_packet_size,
                    "packets_per_second": flow.packets_per_second,
                    "bytes_per_second": flow.bytes_per_second,
                    "tcp_syn_count": flow.tcp_syn_count,
                    "tcp_rst_count": flow.tcp_rst_count,
                    "is_anomaly": anomaly.is_anomaly if anomaly else False,
                    "anomaly_type": anomaly.anomaly_type if anomaly else "",
                    "anomaly_score": anomaly.ensemble_score if anomaly else "",
                    "severity": anomaly.severity if anomaly else "",
                    "explanation": anomaly.explanation if anomaly else "",
                }
            )

    return {"flows": len(flows), "anomalies": len(anomalies)}

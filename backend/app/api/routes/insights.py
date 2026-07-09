from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.anomaly_detector import get_detector
from app.api.schemas import InsightRequest, InsightResponse
from app.database import get_db
from app.flow.statistics import FlowStatistics
from app.llm.explanation_engine import get_explanation_engine
from app.models.anomaly import Anomaly
from app.models.flow import Flow

router = APIRouter(prefix="/insights", tags=["insights"])


@router.post("", response_model=InsightResponse)
async def get_insight(req: InsightRequest, db: AsyncSession = Depends(get_db)) -> InsightResponse:
    flow_row = (
        await db.execute(select(Flow).where(Flow.flow_id == req.flow_id))
    ).scalar_one_or_none()

    if not flow_row:
        raise HTTPException(status_code=404, detail="Flow not found")

    flow_stats = FlowStatistics(
        flow_id=flow_row.flow_id,
        src_ip=flow_row.src_ip,
        dst_ip=flow_row.dst_ip,
        src_port=flow_row.src_port,
        dst_port=flow_row.dst_port,
        protocol=flow_row.protocol,
        packet_count=flow_row.packet_count,
        byte_count=flow_row.byte_count,
        avg_packet_size=flow_row.avg_packet_size,
        duration_seconds=flow_row.duration_seconds,
        packets_per_second=flow_row.packets_per_second,
        bytes_per_second=flow_row.bytes_per_second,
        tcp_syn_count=flow_row.tcp_syn_count,
        tcp_fin_count=flow_row.tcp_fin_count,
        tcp_rst_count=flow_row.tcp_rst_count,
        tcp_ack_count=flow_row.tcp_ack_count,
        tcp_psh_count=flow_row.tcp_psh_count,
        start_time=flow_row.start_time,
        end_time=flow_row.end_time,
    )

    anomaly_row = (
        await db.execute(
            select(Anomaly)
            .where(Anomaly.flow_id == req.flow_id)
            .order_by(Anomaly.detected_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    anomaly_result = None
    if anomaly_row:
        anomaly_result = {
            "is_anomaly": anomaly_row.is_anomaly,
            "anomaly_type": anomaly_row.anomaly_type,
            "ensemble_score": anomaly_row.ensemble_score,
            "severity": anomaly_row.severity,
        }

    engine = get_explanation_engine()
    explanation = await engine.explain_flow(flow_stats, anomaly_result)

    # Persist explanation back to the anomaly row
    if anomaly_row and not anomaly_row.explanation:
        anomaly_row.explanation = explanation
        await db.flush()

    return InsightResponse(
        flow_id=req.flow_id,
        explanation=explanation,
        anomaly_result=anomaly_result,
    )


@router.get("/provider/health")
async def provider_health() -> dict:
    engine = get_explanation_engine()
    ok = await engine.health()
    return {"healthy": ok}

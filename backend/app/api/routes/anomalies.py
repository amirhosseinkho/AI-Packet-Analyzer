from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import AnomalyListResponse, AnomalySchema
from app.database import get_db
from app.models.anomaly import Anomaly

router = APIRouter(prefix="/anomalies", tags=["anomalies"])


@router.get("", response_model=AnomalyListResponse)
async def list_anomalies(
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    only_anomalies: bool = Query(default=True),
    severity: Optional[str] = Query(default=None),
    anomaly_type: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
) -> AnomalyListResponse:
    stmt = select(Anomaly)
    count_stmt = select(func.count()).select_from(Anomaly)

    if only_anomalies:
        stmt = stmt.where(Anomaly.is_anomaly.is_(True))
        count_stmt = count_stmt.where(Anomaly.is_anomaly.is_(True))
    if severity:
        stmt = stmt.where(Anomaly.severity == severity)
        count_stmt = count_stmt.where(Anomaly.severity == severity)
    if anomaly_type:
        stmt = stmt.where(Anomaly.anomaly_type == anomaly_type)
        count_stmt = count_stmt.where(Anomaly.anomaly_type == anomaly_type)

    stmt = stmt.order_by(Anomaly.detected_at.desc()).limit(limit).offset(offset)

    total = (await db.execute(count_stmt)).scalar_one()
    anomalies = (await db.execute(stmt)).scalars().all()

    return AnomalyListResponse(
        total=total,
        anomalies=[AnomalySchema.model_validate(a) for a in anomalies],
    )


@router.get("/{anomaly_id}", response_model=AnomalySchema)
async def get_anomaly(anomaly_id: int, db: AsyncSession = Depends(get_db)) -> AnomalySchema:
    result = await db.execute(select(Anomaly).where(Anomaly.id == anomaly_id))
    anomaly = result.scalar_one_or_none()
    if not anomaly:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return AnomalySchema.model_validate(anomaly)

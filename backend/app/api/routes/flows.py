from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import FlowListResponse, FlowSchema
from app.database import get_db
from app.models.flow import Flow

router = APIRouter(prefix="/flows", tags=["flows"])


@router.get("", response_model=FlowListResponse)
async def list_flows(
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    protocol: Optional[str] = Query(default=None),
    src_ip: Optional[str] = Query(default=None),
    active_only: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
) -> FlowListResponse:
    stmt = select(Flow)
    count_stmt = select(func.count()).select_from(Flow)

    if protocol:
        stmt = stmt.where(Flow.protocol == protocol.upper())
        count_stmt = count_stmt.where(Flow.protocol == protocol.upper())
    if src_ip:
        stmt = stmt.where(Flow.src_ip == src_ip)
        count_stmt = count_stmt.where(Flow.src_ip == src_ip)
    if active_only:
        stmt = stmt.where(Flow.is_active.is_(True))
        count_stmt = count_stmt.where(Flow.is_active.is_(True))

    stmt = stmt.order_by(Flow.start_time.desc()).limit(limit).offset(offset)

    total = (await db.execute(count_stmt)).scalar_one()
    flows = (await db.execute(stmt)).scalars().all()

    return FlowListResponse(
        total=total,
        flows=[FlowSchema.model_validate(f) for f in flows],
    )


@router.get("/{flow_id}", response_model=FlowSchema)
async def get_flow(flow_id: str, db: AsyncSession = Depends(get_db)) -> FlowSchema:
    result = await db.execute(select(Flow).where(Flow.flow_id == flow_id))
    flow = result.scalar_one_or_none()
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return FlowSchema.model_validate(flow)

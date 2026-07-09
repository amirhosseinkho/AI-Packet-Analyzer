from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    CaptureStatusResponse,
    PacketListResponse,
    PacketSchema,
    StartCaptureRequest,
)
from app.capture.capturer import get_capturer
from app.database import get_db
from app.models.packet import Packet

router = APIRouter(prefix="/packets", tags=["packets"])


@router.get("", response_model=PacketListResponse)
async def list_packets(
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    protocol: Optional[str] = Query(default=None),
    src_ip: Optional[str] = Query(default=None),
    dst_ip: Optional[str] = Query(default=None),
    flow_id: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
) -> PacketListResponse:
    stmt = select(Packet)
    count_stmt = select(func.count()).select_from(Packet)

    if protocol:
        stmt = stmt.where(Packet.protocol == protocol.upper())
        count_stmt = count_stmt.where(Packet.protocol == protocol.upper())
    if src_ip:
        stmt = stmt.where(Packet.src_ip == src_ip)
        count_stmt = count_stmt.where(Packet.src_ip == src_ip)
    if dst_ip:
        stmt = stmt.where(Packet.dst_ip == dst_ip)
        count_stmt = count_stmt.where(Packet.dst_ip == dst_ip)
    if flow_id:
        stmt = stmt.where(Packet.flow_id == flow_id)
        count_stmt = count_stmt.where(Packet.flow_id == flow_id)

    stmt = stmt.order_by(Packet.timestamp.desc()).limit(limit).offset(offset)

    total_result = await db.execute(count_stmt)
    total = total_result.scalar_one()
    result = await db.execute(stmt)
    packets = result.scalars().all()

    return PacketListResponse(
        total=total,
        packets=[PacketSchema.model_validate(p) for p in packets],
    )


@router.get("/{packet_id}", response_model=PacketSchema)
async def get_packet(packet_id: int, db: AsyncSession = Depends(get_db)) -> PacketSchema:
    result = await db.execute(select(Packet).where(Packet.id == packet_id))
    packet = result.scalar_one_or_none()
    if not packet:
        raise HTTPException(status_code=404, detail="Packet not found")
    return PacketSchema.model_validate(packet)


@router.get("/capture/status", response_model=CaptureStatusResponse)
async def capture_status() -> CaptureStatusResponse:
    capturer = get_capturer()
    return CaptureStatusResponse(
        running=capturer._running,
        interface=capturer.interface,
        **capturer.stats,
    )


@router.post("/capture/start")
async def start_capture(req: StartCaptureRequest) -> dict:
    capturer = get_capturer()
    if capturer._running:
        return {"status": "already_running"}
    if req.interface:
        capturer.interface = req.interface
    await capturer.start()
    return {"status": "started", "interface": capturer.interface}


@router.post("/capture/stop")
async def stop_capture() -> dict:
    capturer = get_capturer()
    await capturer.stop()
    return {"status": "stopped"}

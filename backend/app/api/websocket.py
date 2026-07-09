from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.capture.capturer import get_capturer
from app.logger import get_logger

log = get_logger(__name__)
router = APIRouter(tags=["websocket"])

_PING_INTERVAL = 20  # seconds


class ConnectionManager:
    def __init__(self) -> None:
        self._active: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._active.add(ws)
        log.debug("WebSocket connected", total=len(self._active))

    def disconnect(self, ws: WebSocket) -> None:
        self._active.discard(ws)
        log.debug("WebSocket disconnected", total=len(self._active))

    async def broadcast(self, data: dict[str, Any]) -> None:
        dead: set[WebSocket] = set()
        payload = json.dumps(data, default=str)
        for ws in list(self._active):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self._active.discard(ws)


manager = ConnectionManager()


@router.websocket("/ws/packets")
async def ws_packets(websocket: WebSocket) -> None:
    """Stream live packets as JSON to every connected client."""
    await manager.connect(websocket)
    capturer = get_capturer()

    async def _ping() -> None:
        while True:
            await asyncio.sleep(_PING_INTERVAL)
            try:
                await websocket.send_text(json.dumps({"type": "ping"}))
            except Exception:
                break

    ping_task = asyncio.create_task(_ping())

    try:
        async for packet in capturer.packets():
            payload = {
                "type": "packet",
                "data": {
                    "timestamp": packet.timestamp.isoformat(),
                    "src_ip": packet.src_ip,
                    "dst_ip": packet.dst_ip,
                    "src_port": packet.src_port,
                    "dst_port": packet.dst_port,
                    "protocol": packet.protocol,
                    "length": packet.length,
                    "tcp_flags": packet.tcp_flags,
                    "flow_id": packet.flow_id,
                    "dns_query": packet.dns_query,
                    "http_host": packet.http_host,
                },
            }
            await manager.broadcast(payload)
    except WebSocketDisconnect:
        pass
    finally:
        ping_task.cancel()
        manager.disconnect(websocket)


@router.websocket("/ws/anomalies")
async def ws_anomalies(websocket: WebSocket) -> None:
    """Push new anomaly events to connected clients."""
    await manager.connect(websocket)
    try:
        # Keep alive – anomalies are pushed via broadcast() from the detection pipeline
        while True:
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)


async def broadcast_anomaly(anomaly_data: dict[str, Any]) -> None:
    """Called by the detection pipeline to push anomaly events."""
    await manager.broadcast({"type": "anomaly", "data": anomaly_data})

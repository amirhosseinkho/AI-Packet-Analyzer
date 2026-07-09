from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from app.capture.parser import ParsedPacket
from app.flow.statistics import FlowStatistics
from app.logger import get_logger

log = get_logger(__name__)

# A flow expires when no new packets are seen within this many seconds.
FLOW_TIMEOUT_SECONDS = 120


class FlowAggregator:
    """Aggregates packets into bidirectional network flows.

    Maintains an in-memory dict keyed by flow_id.  Completed / expired
    flows are emitted to an asyncio.Queue for downstream consumers.
    """

    def __init__(self, flow_timeout: float = FLOW_TIMEOUT_SECONDS) -> None:
        self._flows: dict[str, FlowStatistics] = {}
        self._flow_timeout = flow_timeout
        self._completed: asyncio.Queue[FlowStatistics] = asyncio.Queue()
        self._cleanup_task: Optional[asyncio.Task[None]] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        self._cleanup_task = asyncio.get_running_loop().create_task(self._cleanup_loop())

    async def stop(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
        # Finalise all active flows
        for flow in list(self._flows.values()):
            flow.finalise()
            await self._completed.put(flow)
        self._flows.clear()

    # ── Ingestion ─────────────────────────────────────────────────────────────

    async def ingest(self, packet: ParsedPacket) -> None:
        if not packet.flow_id:
            return

        fid = packet.flow_id
        if fid not in self._flows:
            self._flows[fid] = FlowStatistics(
                flow_id=fid,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
            )

        flow = self._flows[fid]
        flow.add_packet(packet)

        # TCP FIN/RST terminates the flow immediately
        if packet.tcp_flags and ("FIN" in packet.tcp_flags or "RST" in packet.tcp_flags):
            flow.finalise()
            del self._flows[fid]
            await self._completed.put(flow)

    async def completed_flows(self) -> asyncio.Queue[FlowStatistics]:
        return self._completed

    # ── Cleanup loop ──────────────────────────────────────────────────────────

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            now = datetime.now(tz=timezone.utc).timestamp()
            expired = [
                fid
                for fid, flow in self._flows.items()
                if (now - flow.last_seen.timestamp()) > self._flow_timeout
            ]
            for fid in expired:
                flow = self._flows.pop(fid)
                flow.finalise()
                await self._completed.put(flow)
                log.debug("Flow expired", flow_id=fid, packets=flow.packet_count)


_aggregator: Optional[FlowAggregator] = None


def get_aggregator() -> FlowAggregator:
    global _aggregator
    if _aggregator is None:
        _aggregator = FlowAggregator()
    return _aggregator

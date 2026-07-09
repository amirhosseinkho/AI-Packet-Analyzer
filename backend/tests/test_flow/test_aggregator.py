from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest
import pytest_asyncio

from app.capture.parser import ParsedPacket
from app.flow.aggregator import FlowAggregator


def _packet(flow_id: str = "flow1", flags: str = "ACK", protocol: str = "TCP") -> ParsedPacket:
    pkt = ParsedPacket(
        timestamp=datetime.now(tz=timezone.utc),
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=12345,
        dst_port=80,
        protocol=protocol,
        length=500,
        tcp_flags=flags,
    )
    pkt.flow_id = flow_id
    return pkt


@pytest.mark.asyncio
class TestFlowAggregator:
    async def test_ingest_creates_flow(self):
        agg = FlowAggregator()
        await agg.ingest(_packet())
        assert "flow1" in agg._flows
        assert agg._flows["flow1"].packet_count == 1

    async def test_fin_completes_flow(self):
        agg = FlowAggregator()
        await agg.ingest(_packet(flags="SYN"))
        await agg.ingest(_packet(flags="SYNACK"))
        await agg.ingest(_packet(flags="FIN"))
        assert "flow1" not in agg._flows
        queue = await agg.completed_flows()
        assert not queue.empty()

    async def test_rst_completes_flow(self):
        agg = FlowAggregator()
        await agg.ingest(_packet(flags="SYN"))
        await agg.ingest(_packet(flags="RST"))
        assert "flow1" not in agg._flows

    async def test_multiple_flows(self):
        agg = FlowAggregator()
        await agg.ingest(_packet(flow_id="flow1"))
        await agg.ingest(_packet(flow_id="flow2"))
        assert len(agg._flows) == 2

    async def test_stop_finalises_flows(self):
        agg = FlowAggregator()
        await agg.start()
        await agg.ingest(_packet())
        await agg.stop()
        queue = await agg.completed_flows()
        assert not queue.empty()

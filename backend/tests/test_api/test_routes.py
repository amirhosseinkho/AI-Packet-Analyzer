from __future__ import annotations

from datetime import datetime, timezone

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anomaly import Anomaly
from app.models.flow import Flow
from app.models.packet import Packet


async def _seed_packet(db: AsyncSession) -> Packet:
    pkt = Packet(
        timestamp=datetime.now(tz=timezone.utc),
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=443,
        protocol="HTTPS",
        length=1024,
        ttl=64,
        flow_id="testflow001",
    )
    db.add(pkt)
    await db.flush()
    return pkt


async def _seed_flow(db: AsyncSession) -> Flow:
    flow = Flow(
        flow_id="testflow001",
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=443,
        protocol="HTTPS",
        start_time=datetime.now(tz=timezone.utc),
        packet_count=50,
        byte_count=76800,
    )
    db.add(flow)
    await db.flush()
    return flow


async def _seed_anomaly(db: AsyncSession, flow_id: str = "testflow001") -> Anomaly:
    anomaly = Anomaly(
        flow_id=flow_id,
        detector_name="isolation_forest",
        anomaly_score=0.95,
        is_anomaly=True,
        anomaly_type="port_scan",
        ensemble_score=0.91,
        severity="high",
    )
    db.add(anomaly)
    await db.flush()
    return anomaly


@pytest.mark.asyncio
class TestHealth:
    async def test_health_check(self, client: AsyncClient):
        r = await client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


@pytest.mark.asyncio
class TestPacketRoutes:
    async def test_list_packets_empty(self, client: AsyncClient):
        r = await client.get("/api/v1/packets")
        assert r.status_code == 200
        data = r.json()
        assert "packets" in data
        assert "total" in data

    async def test_list_packets_with_data(self, client: AsyncClient, db_session: AsyncSession):
        await _seed_packet(db_session)
        r = await client.get("/api/v1/packets")
        assert r.status_code == 200
        assert r.json()["total"] >= 1

    async def test_filter_by_protocol(self, client: AsyncClient, db_session: AsyncSession):
        await _seed_packet(db_session)
        r = await client.get("/api/v1/packets?protocol=HTTPS")
        assert r.status_code == 200
        packets = r.json()["packets"]
        assert all(p["protocol"] == "HTTPS" for p in packets)

    async def test_packet_not_found(self, client: AsyncClient):
        r = await client.get("/api/v1/packets/999999")
        assert r.status_code == 404


@pytest.mark.asyncio
class TestFlowRoutes:
    async def test_list_flows_empty(self, client: AsyncClient):
        r = await client.get("/api/v1/flows")
        assert r.status_code == 200

    async def test_get_flow(self, client: AsyncClient, db_session: AsyncSession):
        flow = await _seed_flow(db_session)
        r = await client.get(f"/api/v1/flows/{flow.flow_id}")
        assert r.status_code == 200
        assert r.json()["flow_id"] == flow.flow_id

    async def test_flow_not_found(self, client: AsyncClient):
        r = await client.get("/api/v1/flows/nonexistent-flow-id")
        assert r.status_code == 404


@pytest.mark.asyncio
class TestAnomalyRoutes:
    async def test_list_anomalies_empty(self, client: AsyncClient):
        r = await client.get("/api/v1/anomalies")
        assert r.status_code == 200
        assert "anomalies" in r.json()

    async def test_list_anomalies_with_data(self, client: AsyncClient, db_session: AsyncSession):
        await _seed_anomaly(db_session, flow_id="scan001")
        r = await client.get("/api/v1/anomalies")
        assert r.status_code == 200
        assert r.json()["total"] >= 1

    async def test_filter_by_severity(self, client: AsyncClient, db_session: AsyncSession):
        await _seed_anomaly(db_session, flow_id="scan002")
        r = await client.get("/api/v1/anomalies?severity=high")
        assert r.status_code == 200


@pytest.mark.asyncio
class TestStatisticsRoutes:
    async def test_statistics_endpoint(self, client: AsyncClient):
        r = await client.get("/api/v1/statistics")
        assert r.status_code == 200
        data = r.json()
        assert "total_packets" in data
        assert "total_flows" in data
        assert "total_anomalies" in data
        assert "protocol_breakdown" in data


@pytest.mark.asyncio
class TestReportRoutes:
    async def test_list_reports_empty(self, client: AsyncClient):
        r = await client.get("/api/v1/reports")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

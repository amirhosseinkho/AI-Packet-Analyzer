"""Seed the database with synthetic sample data for development."""

from __future__ import annotations

import asyncio
import random
from datetime import datetime, timedelta, timezone

from app.database.connection import AsyncSessionLocal, init_db
from app.models.anomaly import Anomaly
from app.models.flow import Flow
from app.models.packet import Packet

PROTOCOLS = ["TCP", "UDP", "DNS", "HTTPS", "HTTP", "ICMP"]
IPS = ["192.168.1.10", "192.168.1.20", "10.0.0.5", "8.8.8.8", "1.1.1.1", "172.16.0.100"]


async def seed() -> None:
    await init_db()
    async with AsyncSessionLocal() as db:
        now = datetime.now(tz=timezone.utc)

        # Seed packets
        for i in range(200):
            ts = now - timedelta(seconds=random.randint(0, 3600))
            db.add(
                Packet(
                    timestamp=ts,
                    src_ip=random.choice(IPS),
                    dst_ip=random.choice(IPS),
                    src_port=random.randint(1024, 65535),
                    dst_port=random.choice([80, 443, 53, 22, 8080]),
                    protocol=random.choice(PROTOCOLS),
                    length=random.randint(60, 1500),
                    ttl=random.randint(32, 128),
                    flow_id=f"seedflow{i // 5:04d}",
                )
            )

        # Seed flows
        for i in range(40):
            pps = random.uniform(1, 100)
            dur = random.uniform(0.5, 60)
            pkts = int(pps * dur)
            db.add(
                Flow(
                    flow_id=f"seedflow{i:04d}",
                    src_ip=random.choice(IPS),
                    dst_ip=random.choice(IPS),
                    src_port=random.randint(1024, 65535),
                    dst_port=random.choice([80, 443, 53]),
                    protocol=random.choice(PROTOCOLS),
                    start_time=now - timedelta(seconds=dur),
                    duration_seconds=dur,
                    packet_count=pkts,
                    byte_count=pkts * random.randint(200, 1400),
                    packets_per_second=pps,
                    tcp_syn_count=random.randint(0, 5),
                    tcp_ack_count=pkts - 5,
                    is_active=random.choice([True, False]),
                )
            )

        # Seed anomalies
        for i in range(5):
            db.add(
                Anomaly(
                    flow_id=f"seedflow{i:04d}",
                    detector_name="isolation_forest",
                    anomaly_score=random.uniform(0.7, 0.99),
                    is_anomaly=True,
                    anomaly_type=random.choice(["port_scan", "dns_spike", "rst_storm"]),
                    ensemble_score=random.uniform(0.65, 0.95),
                    severity=random.choice(["medium", "high", "critical"]),
                    explanation="Suspicious traffic pattern detected during seeding.",
                )
            )

        await db.commit()
    print("Seed data inserted.")


if __name__ == "__main__":
    asyncio.run(seed())

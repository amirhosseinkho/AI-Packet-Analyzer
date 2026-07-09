"""
Shared test fixtures for PCAP Chat tests.

We don't want to depend on real Scapy captures in CI, so we build
PcapAnalysis objects and DocumentChunks synthetically.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.capture.parser import ParsedPacket
from app.flow.statistics import FlowStatistics
from app.pcap.pcap_processor import DocumentChunk, PcapAnalysis


def make_flow(
    flow_id: str = "flow001",
    protocol: str = "TCP",
    src_ip: str = "192.168.1.10",
    dst_ip: str = "8.8.8.8",
    dst_port: int = 443,
    packet_count: int = 50,
    byte_count: int = 75_000,
    duration: float = 5.0,
    syn: int = 1,
    rst: int = 0,
) -> FlowStatistics:
    flow = FlowStatistics(
        flow_id=flow_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=12345,
        dst_port=dst_port,
        protocol=protocol,
        packet_count=packet_count,
        byte_count=byte_count,
        duration_seconds=duration,
        avg_packet_size=byte_count / max(packet_count, 1),
        packets_per_second=packet_count / max(duration, 0.001),
        bytes_per_second=byte_count / max(duration, 0.001),
        tcp_syn_count=syn,
        tcp_fin_count=1,
        tcp_rst_count=rst,
        tcp_ack_count=packet_count - 2,
        tcp_psh_count=packet_count // 2,
        start_time=datetime.now(tz=timezone.utc),
        is_finalised=True,
    )
    return flow


def make_chunks(n: int = 5) -> list[DocumentChunk]:
    chunks = [
        DocumentChunk(
            chunk_id=f"chunk_{i:03d}",
            category="flow" if i > 0 else "global_summary",
            content=(
                f"Global summary: 1000 packets, 50 flows, 120s duration."
                if i == 0
                else f"Flow {i}: TCP 192.168.1.{i}:5000 → 8.8.8.8:443. "
                     f"Packets: {i * 10}, bytes: {i * 15000}, "
                     f"duration: {i * 2.0}s, rate: {i * 5} pps."
            ),
            metadata={"flow_id": f"flow{i:03d}", "protocol": "TCP"},
        )
        for i in range(n)
    ]
    return chunks


def make_analysis(n_flows: int = 3, n_anomalies: int = 1) -> PcapAnalysis:
    flows = [make_flow(flow_id=f"flow{i:03d}", packet_count=50 + i * 10) for i in range(n_flows)]
    anomaly_results = [
        {
            "flow_id": f"flow{i:03d}",
            "is_anomaly": True,
            "anomaly_type": "port_scan",
            "severity": "high",
            "ensemble_score": 0.85,
        }
        for i in range(n_anomalies)
    ]
    chunks = make_chunks(n_flows + 2)
    return PcapAnalysis(
        filename="test.pcap",
        total_packets=sum(f.packet_count for f in flows),
        total_flows=n_flows,
        duration_seconds=30.0,
        file_size_bytes=50_000,
        flows=flows,
        anomaly_results=anomaly_results,
        chunks=chunks,
        protocol_counts={"TCP": 120, "DNS": 20, "HTTPS": 60},
        top_talkers=[{"ip": "192.168.1.10", "packets": 100, "bytes": 150_000}],
        dns_queries=["google.com", "github.com"],
        http_events=[],
    )

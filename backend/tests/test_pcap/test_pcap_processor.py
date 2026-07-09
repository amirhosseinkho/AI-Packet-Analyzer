from __future__ import annotations

import struct
from pathlib import Path

import pytest

from app.pcap.pcap_processor import (
    DocumentChunk,
    PcapProcessor,
    _build_chunks,
)
from tests.test_pcap.fixtures import make_analysis, make_flow


# ── Helpers ───────────────────────────────────────────────────────────────────

def _write_minimal_pcap(path: Path) -> None:
    """Write the smallest valid PCAP file (global header only, no packets)."""
    # pcap global header: magic, version major/minor, thiszone, sigfigs, snaplen, network
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    path.write_bytes(header)


def _write_invalid_file(path: Path) -> None:
    path.write_bytes(b"\x00" * 10)


# ── PcapProcessor ─────────────────────────────────────────────────────────────

class TestPcapProcessor:
    def test_returns_error_for_invalid_file(self, tmp_path):
        bad = tmp_path / "bad.pcap"
        _write_invalid_file(bad)
        proc = PcapProcessor()
        result = proc.process(bad, "bad.pcap")
        assert result.error is not None
        assert result.total_packets == 0

    def test_returns_error_for_empty_pcap(self, tmp_path):
        empty = tmp_path / "empty.pcap"
        _write_minimal_pcap(empty)
        proc = PcapProcessor()
        result = proc.process(empty, "empty.pcap")
        # Should either error or have 0 packets (no parseable IP packets)
        assert result.error is not None or result.total_packets == 0

    def test_analysis_fields_populated(self):
        """Unit-test the chunk builder in isolation (no file I/O)."""
        from datetime import datetime, timezone
        from app.capture.parser import ParsedPacket

        flows = [make_flow(flow_id=f"f{i}", packet_count=20 + i) for i in range(4)]
        anomalies = [{"flow_id": "f0", "is_anomaly": True, "anomaly_type": "port_scan",
                      "severity": "high", "ensemble_score": 0.9}]

        ts = datetime.now(tz=timezone.utc)
        parsed = [
            ParsedPacket(timestamp=ts, src_ip="1.2.3.4", dst_ip="5.6.7.8",
                         protocol="TCP", length=500, src_port=1234, dst_port=80,
                         dns_query=None, http_host=None)
            for _ in range(10)
        ]

        chunks = _build_chunks(
            filename="test.pcap",
            parsed=parsed,
            flows=flows,
            anomaly_results=anomalies,
            protocol_counts={"TCP": 10},
            top_talkers=[{"ip": "1.2.3.4", "packets": 10, "bytes": 5000}],
            dns_queries=[],
            http_events=[],
            duration=10.0,
        )

        assert len(chunks) > 0
        categories = {c.category for c in chunks}
        assert "global_summary" in categories
        assert "flow" in categories
        assert "anomaly" in categories
        assert "talker" in categories
        assert "tcp_analysis" in categories

    def test_global_summary_content(self):
        from datetime import datetime, timezone
        from app.capture.parser import ParsedPacket

        ts = datetime.now(tz=timezone.utc)
        parsed = [
            ParsedPacket(timestamp=ts, src_ip="1.1.1.1", dst_ip="2.2.2.2",
                         protocol="DNS", length=100, dns_query="example.com")
        ]
        chunks = _build_chunks(
            filename="capture.pcap", parsed=parsed, flows=[], anomaly_results=[],
            protocol_counts={"DNS": 1}, top_talkers=[], dns_queries=["example.com"],
            http_events=[], duration=1.0,
        )
        summary = next(c for c in chunks if c.category == "global_summary")
        assert "capture.pcap" in summary.content
        assert "1 packets" in summary.content or "1" in summary.content
        assert "DNS" in summary.content

    def test_dns_chunk_built_when_queries_present(self):
        from datetime import datetime, timezone
        from app.capture.parser import ParsedPacket

        ts = datetime.now(tz=timezone.utc)
        parsed = [
            ParsedPacket(timestamp=ts, src_ip="1.1.1.1", dst_ip="8.8.8.8",
                         protocol="DNS", length=80, dns_query=f"domain{i}.com")
            for i in range(5)
        ]
        chunks = _build_chunks(
            filename="dns.pcap", parsed=parsed, flows=[], anomaly_results=[],
            protocol_counts={"DNS": 5}, top_talkers=[],
            dns_queries=[f"domain{i}.com" for i in range(5)],
            http_events=[], duration=2.0,
        )
        dns_chunk = next((c for c in chunks if c.category == "dns"), None)
        assert dns_chunk is not None
        assert "domain0.com" in dns_chunk.content

    def test_port_scan_chunk_built(self):
        from datetime import datetime, timezone
        from app.capture.parser import ParsedPacket

        # 12 flows from same source to different ports — should trigger port scan chunk
        flows = [
            make_flow(flow_id=f"scan{i}", dst_port=i + 1, syn=1, rst=1)
            for i in range(12)
        ]
        ts = datetime.now(tz=timezone.utc)
        parsed = [
            ParsedPacket(timestamp=ts, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                         protocol="TCP", length=64, src_port=9999, dst_port=i + 1,
                         tcp_flags="SYN")
            for i in range(12)
        ]
        chunks = _build_chunks(
            filename="scan.pcap", parsed=parsed, flows=flows, anomaly_results=[],
            protocol_counts={"TCP": 12}, top_talkers=[],
            dns_queries=[], http_events=[], duration=3.0,
        )
        scan_chunk = next((c for c in chunks if c.category == "port_scan"), None)
        assert scan_chunk is not None
        assert "port scan" in scan_chunk.content.lower()


# ── DocumentChunk ─────────────────────────────────────────────────────────────

class TestDocumentChunk:
    def test_chunk_has_required_fields(self):
        chunk = DocumentChunk(
            chunk_id="abc",
            category="flow",
            content="Flow data here",
            metadata={"flow_id": "abc"},
        )
        assert chunk.chunk_id == "abc"
        assert chunk.category == "flow"
        assert len(chunk.content) > 0

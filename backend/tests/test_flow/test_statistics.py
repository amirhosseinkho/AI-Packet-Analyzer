from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.capture.parser import ParsedPacket
from app.flow.statistics import FlowStatistics


def _make_packet(length: int = 1000, flags: str = "ACK", protocol: str = "TCP") -> ParsedPacket:
    return ParsedPacket(
        timestamp=datetime.now(tz=timezone.utc),
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=5000,
        dst_port=80,
        protocol=protocol,
        length=length,
        tcp_flags=flags,
    )


class TestFlowStatistics:
    def test_initial_state(self):
        flow = FlowStatistics(flow_id="x", src_ip="a", dst_ip="b", protocol="TCP")
        assert flow.packet_count == 0
        assert flow.byte_count == 0

    def test_add_packet_increments_counts(self):
        flow = FlowStatistics(flow_id="x", src_ip="a", dst_ip="b", protocol="TCP")
        flow.add_packet(_make_packet(500))
        flow.add_packet(_make_packet(1500))
        assert flow.packet_count == 2
        assert flow.byte_count == 2000

    def test_min_max_packet_size(self):
        flow = FlowStatistics(flow_id="x", src_ip="a", dst_ip="b", protocol="TCP")
        flow.add_packet(_make_packet(100))
        flow.add_packet(_make_packet(1400))
        assert flow.min_packet_size == 100
        assert flow.max_packet_size == 1400

    def test_tcp_flag_counting(self):
        flow = FlowStatistics(flow_id="x", src_ip="a", dst_ip="b", protocol="TCP")
        flow.add_packet(_make_packet(flags="SYN"))
        flow.add_packet(_make_packet(flags="SYNACK"))
        flow.add_packet(_make_packet(flags="RST"))
        assert flow.tcp_syn_count == 2
        assert flow.tcp_rst_count == 1

    def test_finalise_computes_rates(self):
        import time
        flow = FlowStatistics(flow_id="x", src_ip="a", dst_ip="b", protocol="TCP")
        flow.add_packet(_make_packet(1000))
        flow.add_packet(_make_packet(1000))
        flow.finalise()
        assert flow.is_finalised
        assert flow.avg_packet_size == 1000.0
        assert flow.duration_seconds is not None
        assert flow.duration_seconds >= 0

    def test_feature_vector_length(self):
        flow = FlowStatistics(flow_id="x", src_ip="a", dst_ip="b", protocol="TCP")
        flow.finalise()
        vec = flow.to_feature_vector()
        assert len(vec) == 13
        assert all(isinstance(v, float) for v in vec)

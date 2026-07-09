from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.capture.parser import ParsedPacket, _decode_tcp_flags, parse_scapy_packet


class TestDecodeTcpFlags:
    def test_syn(self):
        assert "SYN" in _decode_tcp_flags(0x02)

    def test_syn_ack(self):
        flags = _decode_tcp_flags(0x12)
        assert "SYN" in flags
        assert "ACK" in flags

    def test_fin(self):
        assert "FIN" in _decode_tcp_flags(0x01)

    def test_rst(self):
        assert "RST" in _decode_tcp_flags(0x04)

    def test_zero(self):
        assert _decode_tcp_flags(0) == ""


class TestParsedPacket:
    def test_flow_id_is_bidirectional(self):
        p1 = ParsedPacket(
            timestamp=datetime.now(tz=timezone.utc),
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            src_port=1234,
            dst_port=80,
            protocol="TCP",
            length=100,
        )
        p2 = ParsedPacket(
            timestamp=datetime.now(tz=timezone.utc),
            src_ip="5.6.7.8",
            dst_ip="1.2.3.4",
            src_port=80,
            dst_port=1234,
            protocol="TCP",
            length=200,
        )
        assert p1.compute_flow_id() == p2.compute_flow_id()

    def test_flow_id_different_protocol(self):
        p1 = ParsedPacket(
            timestamp=datetime.now(tz=timezone.utc),
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            src_port=1234,
            dst_port=80,
            protocol="TCP",
            length=100,
        )
        p2 = ParsedPacket(
            timestamp=datetime.now(tz=timezone.utc),
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            src_port=1234,
            dst_port=80,
            protocol="UDP",
            length=100,
        )
        assert p1.compute_flow_id() != p2.compute_flow_id()


class TestParseScapyPacket:
    def test_returns_none_when_scapy_unavailable(self):
        with patch.dict("sys.modules", {"scapy.layers.inet": None}):
            result = parse_scapy_packet(MagicMock())
            assert result is None

    def test_returns_none_for_non_ip_non_arp(self):
        mock_pkt = MagicMock()
        mock_pkt.haslayer.return_value = False
        with patch("app.capture.parser.parse_scapy_packet") as mock_parse:
            mock_parse.return_value = None
            assert parse_scapy_packet(mock_pkt) is None

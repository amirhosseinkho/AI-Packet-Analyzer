from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Packet ────────────────────────────────────────────────────────────────────

class PacketSchema(BaseModel):
    id: int
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    ttl: Optional[int]
    tcp_flags: Optional[str]
    payload_preview: Optional[str]
    flow_id: Optional[str]
    dns_query: Optional[str]
    dns_response: Optional[str]
    http_method: Optional[str]
    http_host: Optional[str]
    http_path: Optional[str]
    arp_op: Optional[str]
    arp_hwsrc: Optional[str]
    arp_hwdst: Optional[str]
    inter_arrival_time: Optional[float]

    model_config = {"from_attributes": True}


class PacketListResponse(BaseModel):
    total: int
    packets: list[PacketSchema]


# ── Flow ──────────────────────────────────────────────────────────────────────

class FlowSchema(BaseModel):
    id: int
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    start_time: datetime
    end_time: Optional[datetime]
    duration_seconds: Optional[float]
    packet_count: int
    byte_count: int
    avg_packet_size: Optional[float]
    min_packet_size: Optional[int]
    max_packet_size: Optional[int]
    tcp_syn_count: int
    tcp_fin_count: int
    tcp_rst_count: int
    tcp_ack_count: int
    tcp_psh_count: int
    packets_per_second: Optional[float]
    bytes_per_second: Optional[float]
    is_active: bool

    model_config = {"from_attributes": True}


class FlowListResponse(BaseModel):
    total: int
    flows: list[FlowSchema]


# ── Anomaly ───────────────────────────────────────────────────────────────────

class AnomalySchema(BaseModel):
    id: int
    flow_id: str
    detector_name: str
    anomaly_score: float
    is_anomaly: bool
    anomaly_type: Optional[str]
    ensemble_score: Optional[float]
    explanation: Optional[str]
    severity: Optional[str]
    detected_at: datetime

    model_config = {"from_attributes": True}


class AnomalyListResponse(BaseModel):
    total: int
    anomalies: list[AnomalySchema]


# ── Insights ──────────────────────────────────────────────────────────────────

class InsightRequest(BaseModel):
    flow_id: str


class InsightResponse(BaseModel):
    flow_id: str
    explanation: str
    anomaly_result: Optional[dict[str, Any]] = None


# ── Statistics ────────────────────────────────────────────────────────────────

class ProtocolStats(BaseModel):
    protocol: str
    count: int
    bytes: int
    pct: float


class TrafficStats(BaseModel):
    total_packets: int
    total_bytes: int
    total_flows: int
    total_anomalies: int
    anomaly_rate: float
    protocol_breakdown: list[ProtocolStats]
    top_talkers: list[dict[str, Any]]
    capture_duration_seconds: Optional[float]


# ── Reports ───────────────────────────────────────────────────────────────────

class ReportSchema(BaseModel):
    id: int
    name: str
    format: str
    file_path: str
    file_size_bytes: Optional[int]
    packet_count: int
    flow_count: int
    anomaly_count: int
    period_start: Optional[datetime]
    period_end: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class GenerateReportRequest(BaseModel):
    name: str = Field(default="report")
    format: str = Field(default="json", pattern="^(json|csv|pdf)$")
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None


# ── Capture Control ───────────────────────────────────────────────────────────

class CaptureStatusResponse(BaseModel):
    running: bool
    interface: str
    total_captured: int
    total_dropped: int
    queue_size: int


class StartCaptureRequest(BaseModel):
    interface: Optional[str] = None
    bpf_filter: Optional[str] = None

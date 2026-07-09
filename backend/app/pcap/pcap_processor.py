"""
PCAP Processor
==============
Parses an uploaded PCAP file using Scapy, reconstructs bidirectional flows,
runs the anomaly detector, and converts everything into a flat list of text
chunks that the RAG engine can index and retrieve from.

Each chunk is a self-contained prose fragment so that TF-IDF similarity (and
optional dense embeddings) can surface the most relevant context for a user
question without needing to load the full capture.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app.capture.parser import ParsedPacket, parse_scapy_packet
from app.flow.statistics import FlowStatistics
from app.logger import get_logger

log = get_logger(__name__)


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class DocumentChunk:
    """A single retrievable unit of PCAP knowledge."""
    chunk_id: str
    category: str          # global_summary | flow | anomaly | dns | http | talker
    content: str           # human-readable text fed to TF-IDF / embedding
    metadata: dict         # arbitrary key-value for display / filtering


@dataclass
class PcapAnalysis:
    """Everything extracted from one PCAP file."""
    filename: str
    total_packets: int
    total_flows: int
    duration_seconds: float
    file_size_bytes: int
    flows: list[FlowStatistics]
    anomaly_results: list[dict]              # from AnomalyDetectorService
    chunks: list[DocumentChunk]
    protocol_counts: dict[str, int]
    top_talkers: list[dict]
    dns_queries: list[str]
    http_events: list[dict]
    error: Optional[str] = None


# ── Processor ─────────────────────────────────────────────────────────────────

class PcapProcessor:
    """Synchronous PCAP analysis pipeline.

    Call `process()` from an asyncio executor to avoid blocking the event loop.
    """

    def process(self, path: Path, filename: str = "") -> PcapAnalysis:
        try:
            return self._run(path, filename or path.name)
        except Exception as exc:
            log.error("PCAP processing failed", path=str(path), error=str(exc))
            return PcapAnalysis(
                filename=filename or path.name,
                total_packets=0, total_flows=0, duration_seconds=0.0,
                file_size_bytes=path.stat().st_size if path.exists() else 0,
                flows=[], anomaly_results=[], chunks=[],
                protocol_counts={}, top_talkers=[], dns_queries=[], http_events=[],
                error=str(exc),
            )

    def _run(self, path: Path, filename: str) -> PcapAnalysis:
        try:
            from scapy.utils import rdpcap
        except ImportError as exc:
            raise RuntimeError("Scapy not installed") from exc

        log.info("Reading PCAP", path=str(path))
        raw_pkts = rdpcap(str(path))
        log.info("Loaded packets", count=len(raw_pkts))

        # ── Parse packets ──────────────────────────────────────────────────
        parsed: list[ParsedPacket] = []
        last_time: Optional[float] = None
        for raw in raw_pkts:
            pkt = parse_scapy_packet(raw)
            if pkt is None:
                continue
            now = pkt.timestamp.timestamp()
            pkt.inter_arrival_time = (now - last_time) if last_time else None
            last_time = now
            parsed.append(pkt)

        if not parsed:
            raise ValueError("No parseable IP/ARP packets found in this PCAP file.")

        # ── Aggregate flows ────────────────────────────────────────────────
        flow_map: dict[str, FlowStatistics] = {}
        for pkt in parsed:
            if not pkt.flow_id:
                continue
            fid = pkt.flow_id
            if fid not in flow_map:
                flow_map[fid] = FlowStatistics(
                    flow_id=fid,
                    src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port, dst_port=pkt.dst_port,
                    protocol=pkt.protocol,
                )
            flow_map[fid].add_packet(pkt)
            # TCP teardown closes flow
            if pkt.tcp_flags and ("FIN" in pkt.tcp_flags or "RST" in pkt.tcp_flags):
                flow_map[fid].finalise()

        flows = list(flow_map.values())
        for f in flows:
            if not f.is_finalised:
                f.finalise()

        # ── Anomaly detection ──────────────────────────────────────────────
        anomaly_results: list[dict] = []
        if flows:
            try:
                from app.ai.anomaly_detector import get_detector
                anomaly_results = get_detector().analyse(flows)
            except Exception as exc:
                log.warning("Anomaly detection skipped", error=str(exc))

        # ── Aggregate stats ────────────────────────────────────────────────
        protocol_counts: dict[str, int] = defaultdict(int)
        talker_packets: dict[str, int] = defaultdict(int)
        talker_bytes: dict[str, int] = defaultdict(int)
        dns_queries: list[str] = []
        http_events: list[dict] = []

        for pkt in parsed:
            protocol_counts[pkt.protocol] += 1
            talker_packets[pkt.src_ip] += 1
            talker_bytes[pkt.src_ip] += pkt.length
            if pkt.dns_query:
                dns_queries.append(pkt.dns_query)
            if pkt.http_host:
                http_events.append({
                    "src": pkt.src_ip, "host": pkt.http_host,
                    "method": pkt.http_method, "path": pkt.http_path,
                })

        top_talkers = sorted(
            [{"ip": ip, "packets": talker_packets[ip], "bytes": talker_bytes[ip]}
             for ip in talker_packets],
            key=lambda x: -x["bytes"],
        )[:10]

        ts_list = sorted(p.timestamp for p in parsed)
        duration = (ts_list[-1] - ts_list[0]).total_seconds() if len(ts_list) > 1 else 0.0

        # ── Build chunks ───────────────────────────────────────────────────
        chunks = _build_chunks(
            filename=filename, parsed=parsed, flows=flows,
            anomaly_results=anomaly_results, protocol_counts=dict(protocol_counts),
            top_talkers=top_talkers, dns_queries=list(set(dns_queries)),
            http_events=http_events, duration=duration,
        )

        return PcapAnalysis(
            filename=filename,
            total_packets=len(parsed),
            total_flows=len(flows),
            duration_seconds=duration,
            file_size_bytes=path.stat().st_size,
            flows=flows,
            anomaly_results=anomaly_results,
            chunks=chunks,
            protocol_counts=dict(protocol_counts),
            top_talkers=top_talkers,
            dns_queries=list(set(dns_queries)),
            http_events=http_events,
        )


# ── Chunk builders ────────────────────────────────────────────────────────────

def _cid(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()[:12]


def _build_chunks(
    *,
    filename: str,
    parsed: list[ParsedPacket],
    flows: list[FlowStatistics],
    anomaly_results: list[dict],
    protocol_counts: dict[str, int],
    top_talkers: list[dict],
    dns_queries: list[str],
    http_events: list[dict],
    duration: float,
) -> list[DocumentChunk]:
    chunks: list[DocumentChunk] = []

    # 1. Global summary ───────────────────────────────────────────────────────
    total_bytes = sum(p.length for p in parsed)
    n_anomalies = sum(1 for a in anomaly_results if a.get("is_anomaly"))
    proto_str = ", ".join(
        f"{p} ({c} packets, {c/max(len(parsed),1)*100:.1f}%)"
        for p, c in sorted(protocol_counts.items(), key=lambda x: -x[1])
    )
    summary_text = (
        f"Capture file: {filename}. "
        f"Total packets: {len(parsed)}. "
        f"Total data transferred: {total_bytes/1024:.1f} KB ({total_bytes/1_048_576:.2f} MB). "
        f"Capture duration: {duration:.2f} seconds. "
        f"Unique network flows: {len(flows)}. "
        f"Anomalies detected: {n_anomalies}. "
        f"Protocol breakdown: {proto_str}."
    )
    chunks.append(DocumentChunk(
        chunk_id=_cid("global_summary"),
        category="global_summary",
        content=summary_text,
        metadata={"total_packets": len(parsed), "total_flows": len(flows),
                  "duration_seconds": duration, "anomaly_count": n_anomalies},
    ))

    # 2. Top talkers ──────────────────────────────────────────────────────────
    if top_talkers:
        talker_lines = "; ".join(
            f"{t['ip']} sent {t['packets']} packets ({t['bytes']/1024:.1f} KB)"
            for t in top_talkers[:8]
        )
        chunks.append(DocumentChunk(
            chunk_id=_cid("top_talkers"),
            category="talker",
            content=f"Top hosts by data volume: {talker_lines}.",
            metadata={"talkers": top_talkers},
        ))

    # 3. DNS events ───────────────────────────────────────────────────────────
    if dns_queries:
        unique_dns = list(dict.fromkeys(dns_queries))  # preserve order, deduplicate
        dns_text = (
            f"DNS queries observed ({len(unique_dns)} unique domains): "
            + ", ".join(unique_dns[:60])
            + ("..." if len(unique_dns) > 60 else ".")
        )
        chunks.append(DocumentChunk(
            chunk_id=_cid("dns_events"),
            category="dns",
            content=dns_text,
            metadata={"query_count": len(unique_dns), "queries": unique_dns[:100]},
        ))

    # 4. HTTP events ──────────────────────────────────────────────────────────
    if http_events:
        seen_hosts: dict[str, int] = defaultdict(int)
        for e in http_events:
            if e.get("host"):
                seen_hosts[e["host"]] += 1
        host_str = "; ".join(f"{h} ({n} requests)" for h, n in
                              sorted(seen_hosts.items(), key=lambda x: -x[1])[:20])
        chunks.append(DocumentChunk(
            chunk_id=_cid("http_events"),
            category="http",
            content=(
                f"HTTP traffic observed: {len(http_events)} total requests "
                f"to {len(seen_hosts)} distinct hosts. Top HTTP hosts: {host_str}."
            ),
            metadata={"request_count": len(http_events), "hosts": dict(seen_hosts)},
        ))

    # 5. Per-flow chunks (batch similar small flows) ───────────────────────────
    anomaly_map = {a["flow_id"]: a for a in anomaly_results}
    for flow in flows:
        anom = anomaly_map.get(flow.flow_id, {})
        flags_str = (
            f"TCP flags — SYN:{flow.tcp_syn_count} FIN:{flow.tcp_fin_count} "
            f"RST:{flow.tcp_rst_count} ACK:{flow.tcp_ack_count} PSH:{flow.tcp_psh_count}. "
            if flow.protocol in ("TCP", "HTTP", "HTTPS") else ""
        )
        anom_str = ""
        if anom.get("is_anomaly"):
            anom_str = (
                f"ANOMALY DETECTED — type: {anom.get('anomaly_type','unknown')}, "
                f"severity: {anom.get('severity','?')}, "
                f"ensemble score: {anom.get('ensemble_score',0):.3f}. "
            )
        flow_text = (
            f"Flow {flow.flow_id[:8]}: {flow.protocol} "
            f"{flow.src_ip}:{flow.src_port or '*'} → {flow.dst_ip}:{flow.dst_port or '*'}. "
            f"Packets: {flow.packet_count}, bytes: {flow.byte_count}, "
            f"duration: {flow.duration_seconds:.3f}s, "
            f"avg packet size: {flow.avg_packet_size:.0f}B, "
            f"rate: {flow.packets_per_second:.1f} pps / {(flow.bytes_per_second or 0)/1024:.1f} KB/s. "
            f"{flags_str}{anom_str}"
        )
        chunks.append(DocumentChunk(
            chunk_id=_cid(f"flow_{flow.flow_id}"),
            category="flow",
            content=flow_text,
            metadata={
                "flow_id": flow.flow_id,
                "src_ip": flow.src_ip, "dst_ip": flow.dst_ip,
                "protocol": flow.protocol,
                "is_anomaly": anom.get("is_anomaly", False),
                "anomaly_type": anom.get("anomaly_type"),
            },
        ))

    # 6. Anomaly summary chunk ─────────────────────────────────────────────────
    anomalous = [a for a in anomaly_results if a.get("is_anomaly")]
    if anomalous:
        by_type: dict[str, list] = defaultdict(list)
        for a in anomalous:
            by_type[a.get("anomaly_type") or "unknown"].append(a)
        type_summary = "; ".join(
            f"{len(v)} {t} event(s)" for t, v in sorted(by_type.items())
        )
        sev_counts: dict[str, int] = defaultdict(int)
        for a in anomalous:
            sev_counts[a.get("severity", "unknown")] += 1
        sev_str = ", ".join(f"{k}: {v}" for k, v in sev_counts.items())
        chunks.append(DocumentChunk(
            chunk_id=_cid("anomaly_summary"),
            category="anomaly",
            content=(
                f"Anomaly summary: {len(anomalous)} anomalous flows detected out of {len(flows)} total. "
                f"Types observed: {type_summary}. Severity breakdown: {sev_str}. "
                + "Anomalous flow IDs: "
                + ", ".join(a["flow_id"][:8] for a in anomalous[:20])
                + ("..." if len(anomalous) > 20 else ".")
            ),
            metadata={"anomaly_count": len(anomalous), "by_type": dict(by_type),
                      "severity_counts": dict(sev_counts)},
        ))

    # 7. TCP handshake analysis ────────────────────────────────────────────────
    tcp_flows = [f for f in flows if f.protocol in ("TCP", "HTTP", "HTTPS")]
    if tcp_flows:
        incomplete = [f for f in tcp_flows if f.tcp_syn_count > 0 and f.tcp_ack_count == 0]
        resets = [f for f in tcp_flows if f.tcp_rst_count > 5]
        retrans_hint = [f for f in tcp_flows
                        if (f.packet_count or 0) > 10
                        and (f.avg_packet_size or 0) < 80
                        and f.tcp_ack_count > f.packet_count * 0.6]
        handshake_text = (
            f"TCP analysis over {len(tcp_flows)} TCP/HTTP/HTTPS flows: "
            f"{len(incomplete)} flows with SYN but no ACK (possible incomplete handshakes or filtered ports). "
            f"{len(resets)} flows with high RST count (possible connection rejections or scanning). "
            f"{len(retrans_hint)} flows show possible retransmission patterns (many small ACKs). "
        )
        if incomplete:
            handshake_text += (
                "Incomplete handshake flows involve: "
                + ", ".join(f"{f.src_ip}→{f.dst_ip}:{f.dst_port}" for f in incomplete[:10])
                + ". "
            )
        chunks.append(DocumentChunk(
            chunk_id=_cid("tcp_analysis"),
            category="tcp_analysis",
            content=handshake_text,
            metadata={
                "tcp_flow_count": len(tcp_flows),
                "incomplete_handshakes": len(incomplete),
                "rst_storms": len(resets),
                "retransmission_hint_count": len(retrans_hint),
            },
        ))

    # 8. Port scan detection heuristic ────────────────────────────────────────
    syn_per_src: dict[str, set] = defaultdict(set)
    for flow in tcp_flows:
        if flow.tcp_syn_count > 0:
            syn_per_src[flow.src_ip].add(flow.dst_port)
    scanners = {ip: ports for ip, ports in syn_per_src.items() if len(ports) >= 10}
    if scanners:
        scan_text = (
            f"Potential port scan activity detected from {len(scanners)} source IP(s). "
            + " ".join(
                f"{ip} probed {len(ports)} distinct ports (e.g. {sorted(ports)[:8]})."
                for ip, ports in list(scanners.items())[:5]
            )
        )
        chunks.append(DocumentChunk(
            chunk_id=_cid("port_scan_heuristic"),
            category="port_scan",
            content=scan_text,
            metadata={"scanners": {ip: sorted(p) for ip, p in scanners.items()}},
        ))

    log.info("Built PCAP chunks", total=len(chunks))
    return chunks

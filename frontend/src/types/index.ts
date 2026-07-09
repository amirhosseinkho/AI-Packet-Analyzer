export interface Packet {
  id: number
  timestamp: string
  src_ip: string
  dst_ip: string
  src_port: number | null
  dst_port: number | null
  protocol: string
  length: number
  ttl: number | null
  tcp_flags: string | null
  payload_preview: string | null
  flow_id: string | null
  dns_query: string | null
  dns_response: string | null
  http_method: string | null
  http_host: string | null
  http_path: string | null
  arp_op: string | null
  arp_hwsrc: string | null
  arp_hwdst: string | null
  inter_arrival_time: number | null
}

export interface Flow {
  id: number
  flow_id: string
  src_ip: string
  dst_ip: string
  src_port: number | null
  dst_port: number | null
  protocol: string
  start_time: string
  end_time: string | null
  duration_seconds: number | null
  packet_count: number
  byte_count: number
  avg_packet_size: number | null
  min_packet_size: number | null
  max_packet_size: number | null
  tcp_syn_count: number
  tcp_fin_count: number
  tcp_rst_count: number
  tcp_ack_count: number
  tcp_psh_count: number
  packets_per_second: number | null
  bytes_per_second: number | null
  is_active: boolean
}

export interface Anomaly {
  id: number
  flow_id: string
  detector_name: string
  anomaly_score: number
  is_anomaly: boolean
  anomaly_type: string | null
  ensemble_score: number | null
  explanation: string | null
  severity: 'low' | 'medium' | 'high' | 'critical' | null
  detected_at: string
}

export interface ProtocolStats {
  protocol: string
  count: number
  bytes: number
  pct: number
}

export interface TrafficStats {
  total_packets: number
  total_bytes: number
  total_flows: number
  total_anomalies: number
  anomaly_rate: number
  protocol_breakdown: ProtocolStats[]
  top_talkers: { ip: string; packets: number; bytes: number }[]
  capture_duration_seconds: number | null
}

export interface Report {
  id: number
  name: string
  format: string
  file_path: string
  file_size_bytes: number | null
  packet_count: number
  flow_count: number
  anomaly_count: number
  period_start: string | null
  period_end: string | null
  created_at: string
}

export type WsMessage =
  | { type: 'packet'; data: Partial<Packet> }
  | { type: 'anomaly'; data: Partial<Anomaly> }
  | { type: 'ping' }

// ── PCAP Chat ─────────────────────────────────────────────────────────────────

export interface PcapUploadResponse {
  session_id: string
  filename: string
  total_packets: number
  total_flows: number
  total_anomalies: number
  duration_seconds: number
  chunk_count: number
  protocol_counts: Record<string, number>
  top_talkers: { ip: string; packets: number; bytes: number }[]
  dns_query_count: number
  llm_provider: string
  embedding_index: boolean
  error: string | null
}

export interface SourceChunk {
  category: string
  content: string
  score: number
  metadata: Record<string, unknown>
}

export interface PcapChatResponse {
  session_id: string
  question: string
  answer: string
  sources: SourceChunk[]
  message_index: number
}

export interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  sources: SourceChunk[]
}

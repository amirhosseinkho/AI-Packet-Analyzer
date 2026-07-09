# API Reference

Base URL: `http://localhost:8000/api/v1`

Interactive Swagger UI: `http://localhost:8000/api/docs`

---

## Packets

### `GET /packets`

List captured packets with optional filters.

**Query parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 100 | Max results (≤ 1000) |
| `offset` | int | 0 | Pagination offset |
| `protocol` | str | — | Filter by protocol (TCP, UDP, DNS…) |
| `src_ip` | str | — | Filter by source IP |
| `dst_ip` | str | — | Filter by destination IP |
| `flow_id` | str | — | Filter by flow ID |

**Response:** `{ total: int, packets: Packet[] }`

### `GET /packets/{id}`

Get a single packet by ID. Returns 404 if not found.

### `GET /packets/capture/status`

Returns capture state: `running`, `interface`, `total_captured`, `total_dropped`, `queue_size`.

### `POST /packets/capture/start`

Start packet capture. Body: `{ interface?: string, bpf_filter?: string }`.

### `POST /packets/capture/stop`

Stop the active capture.

---

## Flows

### `GET /flows`

List network flows.

**Query parameters:** `limit`, `offset`, `protocol`, `src_ip`, `active_only: bool`

### `GET /flows/{flow_id}`

Get a single flow by its MD5 flow ID.

---

## Anomalies

### `GET /anomalies`

List anomaly detections.

**Query parameters:** `limit`, `offset`, `only_anomalies: bool` (default true), `severity`, `anomaly_type`

Severity values: `low | medium | high | critical`

### `GET /anomalies/{id}`

Get a single anomaly record.

---

## Insights (LLM)

### `POST /insights`

Request an AI-generated explanation for a specific flow.

**Body:** `{ flow_id: string }`

**Response:**
```json
{
  "flow_id": "abc123...",
  "explanation": "Normal HTTPS browsing traffic from 192.168.1.5 to a CDN endpoint...",
  "anomaly_result": { "is_anomaly": false, "ensemble_score": 0.12 }
}
```

### `GET /insights/provider/health`

Returns `{ healthy: bool }` — checks if the configured LLM provider is reachable.

---

## Statistics

### `GET /statistics`

Aggregate traffic statistics.

**Response:**
```json
{
  "total_packets": 125430,
  "total_bytes": 98432000,
  "total_flows": 3421,
  "total_anomalies": 17,
  "anomaly_rate": 0.49,
  "protocol_breakdown": [
    { "protocol": "TCP", "count": 80000, "bytes": 70000000, "pct": 63.78 }
  ],
  "top_talkers": [
    { "ip": "192.168.1.10", "packets": 25000, "bytes": 30000000 }
  ],
  "capture_duration_seconds": 3600
}
```

---

## Reports

### `POST /reports`

Generate a report.

**Body:** `{ name: string, format: "json"|"csv"|"pdf", period_start?: ISO8601, period_end?: ISO8601 }`

### `GET /reports`

List all generated reports.

### `GET /reports/{id}/download`

Download a report file. Returns the file with appropriate `Content-Type`.

---

## WebSocket Endpoints

### `ws://localhost:8000/ws/packets`

Streams live packet events. Each message is JSON:

```json
{ "type": "packet", "data": { "timestamp": "...", "src_ip": "...", "protocol": "TCP", ... } }
```

Heartbeat ping every 20 seconds:
```json
{ "type": "ping" }
```

### `ws://localhost:8000/ws/anomalies`

Pushes anomaly detection events in real-time:

```json
{ "type": "anomaly", "data": { "flow_id": "...", "severity": "high", "anomaly_type": "port_scan", ... } }
```

# Architecture

## Overview

AI Packet Analyzer uses a clean layered architecture where each layer has a single responsibility and communicates through typed interfaces.

```
Network Interface
       │
       ▼
┌─────────────────────────────────┐
│         Capture Layer           │  Scapy sniffer thread → asyncio queue
│  capturer.py  parser.py         │
└──────────────┬──────────────────┘
               │ ParsedPacket stream
               ▼
┌─────────────────────────────────┐
│          Flow Layer             │  Bidirectional flow aggregation
│  aggregator.py  statistics.py   │
└──────────────┬──────────────────┘
               │ FlowStatistics
               ▼
┌─────────────────────────────────┐
│            AI Layer             │  Ensemble anomaly detection
│  isolation_forest.py            │
│  autoencoder.py                 │
│  feature_extractor.py           │
└──────────────┬──────────────────┘
               │ AnomalyResult + FlowStatistics
               ▼
┌─────────────────────────────────┐
│           LLM Layer             │  Natural language explanation
│  explanation_engine.py          │
│  providers/ollama_provider.py   │
│  providers/openai_provider.py   │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│           API Layer             │  FastAPI + WebSocket
│  routes/{packets,flows,...}     │
│  websocket.py                   │
└──────────────┬──────────────────┘
               │
       ┌───────┴────────┐
       ▼                ▼
  PostgreSQL       React Frontend
  (SQLAlchemy)   (Vite + Tailwind)
```

## Key Design Decisions

### Async Capture Pipeline

Scapy's sniffer runs in a `ThreadPoolExecutor` thread and forwards packets to the async event loop via `asyncio.Queue`. This prevents the capture I/O from blocking FastAPI's event loop.

### Bidirectional Flow Key

Flow ID is computed as `MD5(sorted([src:port, dst:port]) + protocol)`. Sorting the endpoints makes the key symmetric — packets flowing in both directions map to the same flow.

### Ensemble Anomaly Detection

Both Isolation Forest (tree-based, global) and Autoencoder (neural, reconstruction-error) scores are averaged into an `ensemble_score`. This reduces false positives from either model.

### LLM Provider Abstraction

`BaseLLMProvider` defines the `complete()` contract. Swapping between Ollama and OpenAI requires only changing `LLM_PROVIDER` in `.env`. A `MockProvider` is used in tests for deterministic, zero-latency responses.

### Database

All four entities (`Packet`, `Flow`, `Anomaly`, `Report`) are stored in PostgreSQL via async SQLAlchemy. Packets are indexed on `(timestamp, src_ip, dst_ip, protocol, flow_id)` for fast dashboard queries.

## Data Flow Sequence

```
1. PacketCapturer.start() → Scapy AsyncSniffer runs in thread
2. Each raw packet → parse_scapy_packet() → ParsedPacket
3. ParsedPacket → FlowAggregator.ingest() → updates FlowStatistics
4. On FIN/RST/timeout → FlowStatistics.finalise() → emitted to queue
5. Pipeline picks up completed flow → persists to Flow table
6. FeatureExtractor.transform() → normalised numpy array
7. IsolationForestDetector + AutoencoderDetector → scores
8. AnomalyDetectorService.analyse() → ensemble result → Anomaly table
9. ExplanationEngine.explain_flow() → LLM call → explanation text stored
10. WebSocket broadcaster pushes live events to connected clients
```

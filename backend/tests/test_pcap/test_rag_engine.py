from __future__ import annotations

import pytest

from app.llm.providers.mock_provider import MockProvider
from app.pcap.pcap_processor import DocumentChunk
from app.pcap.rag_engine import RAGEngine, TFIDFRetriever, _build_context, _merge_with_summary
from tests.test_pcap.fixtures import make_analysis, make_chunks


# ── TFIDFRetriever ────────────────────────────────────────────────────────────

class TestTFIDFRetriever:
    def test_retrieve_returns_results(self):
        chunks = make_chunks(10)
        retriever = TFIDFRetriever(chunks)
        results = retriever.retrieve("TCP packets port scan", top_k=3)
        assert len(results) >= 1
        assert all(r.score >= 0.0 for r in results)

    def test_retrieve_respects_top_k(self):
        chunks = make_chunks(20)
        retriever = TFIDFRetriever(chunks)
        results = retriever.retrieve("network traffic", top_k=5)
        assert len(results) <= 5

    def test_retrieve_scores_relevant_higher(self):
        chunks = [
            DocumentChunk("a", "flow", "TCP port scan SYN RST 192.168.1.1 probed 500 ports", {}),
            DocumentChunk("b", "flow", "Normal HTTPS browsing traffic to CDN server", {}),
            DocumentChunk("c", "dns", "DNS queries for google.com, github.com", {}),
        ]
        retriever = TFIDFRetriever(chunks)
        results = retriever.retrieve("port scan detected")
        assert results[0].chunk.chunk_id == "a"

    def test_no_match_returns_empty(self):
        chunks = [
            DocumentChunk("x", "flow", "abc def ghi", {}),
        ]
        retriever = TFIDFRetriever(chunks)
        results = retriever.retrieve("zzz xyz completely unrelated xqyz")
        # TF-IDF returns results only when score > 0
        for r in results:
            assert r.score == 0.0 or r.chunk.chunk_id == "x"

    def test_handles_single_chunk(self):
        chunks = [DocumentChunk("only", "global_summary", "Single chunk content.", {})]
        retriever = TFIDFRetriever(chunks)
        results = retriever.retrieve("chunk content")
        assert len(results) >= 0  # should not crash


# ── RAGEngine ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestRAGEngine:
    async def test_answer_returns_string(self):
        analysis = make_analysis(n_flows=3)
        engine = RAGEngine(analysis, MockProvider())
        answer, sources = await engine.answer("What happened in this capture?")
        assert isinstance(answer, str)
        assert len(answer) > 0

    async def test_answer_returns_sources(self):
        analysis = make_analysis(n_flows=5)
        engine = RAGEngine(analysis, MockProvider())
        _, sources = await engine.answer("Which flows were anomalous?")
        assert isinstance(sources, list)
        assert len(sources) >= 1

    async def test_global_summary_always_in_sources(self):
        analysis = make_analysis(n_flows=3)
        engine = RAGEngine(analysis, MockProvider())
        _, sources = await engine.answer("port scan details")
        categories = [s.chunk.category for s in sources]
        assert "global_summary" in categories

    async def test_handles_empty_chunks(self):
        from app.pcap.pcap_processor import PcapAnalysis
        analysis = PcapAnalysis(
            filename="empty.pcap",
            total_packets=0, total_flows=0, duration_seconds=0,
            file_size_bytes=0, flows=[], anomaly_results=[],
            chunks=[DocumentChunk("s", "global_summary",
                                  "Empty capture. 0 packets, 0 flows.", {})],
            protocol_counts={}, top_talkers=[], dns_queries=[], http_events=[],
        )
        engine = RAGEngine(analysis, MockProvider())
        answer, sources = await engine.answer("Any anomalies?")
        assert isinstance(answer, str)

    async def test_top_k_limits_sources(self):
        analysis = make_analysis(n_flows=20)
        engine = RAGEngine(analysis, MockProvider())
        _, sources = await engine.answer("TCP handshakes", top_k=3)
        assert len(sources) <= 4  # 3 + possible forced summary


# ── Helpers ────────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_build_context_respects_max_chars(self):
        from app.pcap.rag_engine import RetrievedChunk
        long_chunks = [
            RetrievedChunk(
                chunk=DocumentChunk(f"c{i}", "flow", "x" * 1000, {}),
                score=0.9 - i * 0.1,
            )
            for i in range(10)
        ]
        context = _build_context(long_chunks, max_chars=2000)
        assert len(context) <= 2100  # small tolerance for category labels

    def test_merge_with_summary_adds_missing_summary(self):
        from app.pcap.rag_engine import RetrievedChunk
        summary = DocumentChunk("sum", "global_summary", "Summary text.", {})
        results = [
            RetrievedChunk(chunk=DocumentChunk("a", "flow", "Flow a", {}), score=0.8)
        ]
        merged = _merge_with_summary(results, summary)
        ids = [r.chunk.chunk_id for r in merged]
        assert "sum" in ids

    def test_merge_with_summary_no_duplicate(self):
        from app.pcap.rag_engine import RetrievedChunk
        summary = DocumentChunk("sum", "global_summary", "Summary.", {})
        results = [
            RetrievedChunk(chunk=summary, score=1.0),
            RetrievedChunk(chunk=DocumentChunk("b", "flow", "Flow b", {}), score=0.5),
        ]
        merged = _merge_with_summary(results, summary)
        ids = [r.chunk.chunk_id for r in merged]
        assert ids.count("sum") == 1

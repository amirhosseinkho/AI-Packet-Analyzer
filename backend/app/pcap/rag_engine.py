"""
RAG Engine
==========
Two-stage retrieval-augmented generation over a PCAP analysis:

  Stage 1 – Retrieval
    Primary:  Ollama /api/embeddings → cosine similarity (dense, semantic)
    Fallback: sklearn TF-IDF → cosine similarity (sparse, keyword)

  Stage 2 – Generation
    Injects the top-k retrieved chunks as context into an LLM prompt.
    Uses the same BaseLLMProvider abstraction as the rest of the project.
"""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from app.llm.providers.base import BaseLLMProvider
from app.logger import get_logger
from app.pcap.pcap_processor import DocumentChunk, PcapAnalysis

log = get_logger(__name__)

_TOP_K = 6
_MAX_CONTEXT_CHARS = 3_000

_SYSTEM_PROMPT = """You are an expert network security analyst AI.
You have been given extracted context from a PCAP (packet capture) file.
Answer the user's question accurately and concisely using only the provided context.
If the context does not contain enough information to answer confidently, say so.
Use technical network terminology where appropriate.
Do NOT fabricate IP addresses, flow IDs, or statistics that are not in the context."""


# ── Retrieved source ──────────────────────────────────────────────────────────

@dataclass
class RetrievedChunk:
    chunk: DocumentChunk
    score: float


# ── Retriever interface ───────────────────────────────────────────────────────

class TFIDFRetriever:
    """Sparse keyword retriever using sklearn TF-IDF + cosine similarity."""

    def __init__(self, chunks: list[DocumentChunk]) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity as sk_cosine

        self._chunks = chunks
        self._sk_cosine = sk_cosine
        corpus = [c.content for c in chunks]
        self._vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            sublinear_tf=True,
            min_df=1,
            stop_words="english",
        )
        self._matrix = self._vectorizer.fit_transform(corpus)

    def retrieve(self, query: str, top_k: int = _TOP_K) -> list[RetrievedChunk]:
        q_vec = self._vectorizer.transform([query])
        scores = self._sk_cosine(q_vec, self._matrix)[0]
        top_indices = np.argsort(scores)[::-1][:top_k]
        return [
            RetrievedChunk(chunk=self._chunks[i], score=float(scores[i]))
            for i in top_indices
            if scores[i] > 0.0
        ]


class EmbeddingRetriever:
    """Dense semantic retriever using Ollama /api/embeddings endpoint."""

    def __init__(self, chunks: list[DocumentChunk], ollama_url: str, model: str) -> None:
        self._chunks = chunks
        self._url = ollama_url.rstrip("/")
        self._model = model
        self._embeddings: Optional[np.ndarray] = None

    async def build_index(self) -> bool:
        """Pre-compute embeddings for all chunks. Returns False if Ollama unavailable."""
        try:
            import httpx
            vecs = []
            async with httpx.AsyncClient(timeout=60.0) as client:
                for chunk in self._chunks:
                    r = await client.post(
                        f"{self._url}/api/embeddings",
                        json={"model": self._model, "prompt": chunk.content},
                    )
                    r.raise_for_status()
                    vecs.append(r.json()["embedding"])
            self._embeddings = np.array(vecs, dtype=np.float32)
            # L2-normalise for cosine similarity via dot product
            norms = np.linalg.norm(self._embeddings, axis=1, keepdims=True)
            self._embeddings /= np.where(norms == 0, 1, norms)
            log.info("Embedding index built", chunks=len(self._chunks))
            return True
        except Exception as exc:
            log.warning("Embedding index failed, will use TF-IDF fallback", error=str(exc))
            return False

    async def retrieve(self, query: str, top_k: int = _TOP_K) -> list[RetrievedChunk]:
        if self._embeddings is None:
            return []
        import httpx
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                f"{self._url}/api/embeddings",
                json={"model": self._model, "prompt": query},
            )
            r.raise_for_status()
            q_vec = np.array(r.json()["embedding"], dtype=np.float32)
        norm = np.linalg.norm(q_vec)
        if norm > 0:
            q_vec /= norm
        scores = self._embeddings @ q_vec
        top_indices = np.argsort(scores)[::-1][:top_k]
        return [
            RetrievedChunk(chunk=self._chunks[i], score=float(scores[i]))
            for i in top_indices
        ]


# ── RAG Engine ────────────────────────────────────────────────────────────────

class RAGEngine:
    """
    Builds a retrieval index over a PcapAnalysis and answers natural-language
    questions by combining retrieved context with LLM generation.
    """

    def __init__(self, analysis: PcapAnalysis, provider: BaseLLMProvider) -> None:
        self._analysis = analysis
        self._provider = provider
        self._tfidf = TFIDFRetriever(analysis.chunks)
        self._embedding: Optional[EmbeddingRetriever] = None
        self._use_embeddings = False

    async def build_embedding_index(self, ollama_url: str, model: str) -> bool:
        self._embedding = EmbeddingRetriever(self._analysis.chunks, ollama_url, model)
        ok = await self._embedding.build_index()
        self._use_embeddings = ok
        return ok

    async def answer(
        self,
        question: str,
        top_k: int = _TOP_K,
        temperature: float = 0.2,
    ) -> tuple[str, list[RetrievedChunk]]:
        """
        Returns (answer_text, retrieved_sources).
        """
        sources = await self._retrieve(question, top_k)
        context = _build_context(sources, max_chars=_MAX_CONTEXT_CHARS)
        prompt = _build_prompt(question, context, self._analysis)

        try:
            answer = await self._provider.complete(
                prompt=prompt,
                system=_SYSTEM_PROMPT,
                temperature=temperature,
                max_tokens=768,
            )
        except Exception as exc:
            log.error("LLM answer generation failed", error=str(exc))
            answer = (
                "I was unable to generate an answer because the LLM provider "
                f"returned an error: {exc}. "
                "Here is the most relevant context I found:\n\n"
                + "\n\n".join(s.chunk.content for s in sources[:3])
            )

        return answer.strip(), sources

    async def _retrieve(self, query: str, top_k: int) -> list[RetrievedChunk]:
        # Always ensure the global_summary chunk is included
        summary_chunk = next(
            (c for c in self._analysis.chunks if c.category == "global_summary"), None
        )

        if self._use_embeddings and self._embedding:
            try:
                results = await self._embedding.retrieve(query, top_k=top_k)
                if results:
                    return _merge_with_summary(results, summary_chunk)
            except Exception as exc:
                log.warning("Embedding retrieval failed, falling back to TF-IDF", error=str(exc))

        results = self._tfidf.retrieve(query, top_k=top_k)
        return _merge_with_summary(results, summary_chunk)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _merge_with_summary(
    results: list[RetrievedChunk],
    summary: Optional[DocumentChunk],
) -> list[RetrievedChunk]:
    """Ensure global_summary is always in the context."""
    if summary is None:
        return results
    ids = {r.chunk.chunk_id for r in results}
    if summary.chunk_id not in ids:
        return [RetrievedChunk(chunk=summary, score=1.0)] + results
    return results


def _build_context(sources: list[RetrievedChunk], max_chars: int) -> str:
    parts: list[str] = []
    used = 0
    for src in sources:
        snippet = src.chunk.content
        if used + len(snippet) > max_chars:
            snippet = snippet[: max_chars - used] + "…"
        parts.append(f"[{src.chunk.category.upper()}] {snippet}")
        used += len(snippet)
        if used >= max_chars:
            break
    return "\n\n".join(parts)


def _build_prompt(question: str, context: str, analysis: PcapAnalysis) -> str:
    return (
        f"PCAP file: {analysis.filename} "
        f"({analysis.total_packets} packets, {analysis.total_flows} flows, "
        f"{analysis.duration_seconds:.1f}s duration)\n\n"
        f"--- CONTEXT ---\n{context}\n--- END CONTEXT ---\n\n"
        f"Question: {question}"
    )

"""
PCAP Chat Session Store
=======================
Keeps RAGEngine instances and chat histories alive in memory for the lifetime
of a session (TTL-evicted).  Session *metadata* (filename, chunk count, etc.)
is written to the database separately via the PcapSession ORM model.

Design rationale:
  - RAG indices can be several MB per capture; we don't serialise them to the DB.
  - Sessions are keyed by a UUID and expire after SESSION_TTL_SECONDS of
    inactivity so memory doesn't grow unboundedly.
  - A single asyncio.Lock per session prevents concurrent LLM calls producing
    interleaved responses in the chat history.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from app.logger import get_logger
from app.pcap.pcap_processor import PcapAnalysis
from app.pcap.rag_engine import RAGEngine

log = get_logger(__name__)

SESSION_TTL_SECONDS = 3600  # 1 hour idle timeout


@dataclass
class ChatMessage:
    role: str          # "user" | "assistant"
    content: str
    sources: list[dict] = field(default_factory=list)   # snippet of retrieved chunks
    timestamp: float = field(default_factory=time.time)


@dataclass
class PcapChatSession:
    session_id: str
    filename: str
    analysis: PcapAnalysis
    engine: RAGEngine
    history: list[ChatMessage] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def touch(self) -> None:
        self.last_active = time.time()

    def is_expired(self) -> bool:
        return (time.time() - self.last_active) > SESSION_TTL_SECONDS

    def summary_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "filename": self.filename,
            "total_packets": self.analysis.total_packets,
            "total_flows": self.analysis.total_flows,
            "total_anomalies": len([a for a in self.analysis.anomaly_results if a.get("is_anomaly")]),
            "duration_seconds": self.analysis.duration_seconds,
            "chunk_count": len(self.analysis.chunks),
            "protocol_counts": self.analysis.protocol_counts,
            "top_talkers": self.analysis.top_talkers[:5],
            "dns_query_count": len(self.analysis.dns_queries),
            "created_at": self.created_at,
            "message_count": len(self.history),
            "error": self.analysis.error,
        }


class SessionStore:
    """Thread-safe in-memory store with TTL eviction."""

    def __init__(self) -> None:
        self._sessions: dict[str, PcapChatSession] = {}
        self._lock = asyncio.Lock()

    def new_id(self) -> str:
        return str(uuid.uuid4())

    async def put(self, session: PcapChatSession) -> None:
        async with self._lock:
            self._sessions[session.session_id] = session
            self._evict_expired()

    async def get(self, session_id: str) -> Optional[PcapChatSession]:
        async with self._lock:
            session = self._sessions.get(session_id)
        if session and session.is_expired():
            await self.delete(session_id)
            return None
        if session:
            session.touch()
        return session

    async def delete(self, session_id: str) -> None:
        async with self._lock:
            self._sessions.pop(session_id, None)
        log.info("PCAP session evicted", session_id=session_id)

    async def list_sessions(self) -> list[dict]:
        async with self._lock:
            return [s.summary_dict() for s in self._sessions.values() if not s.is_expired()]

    def _evict_expired(self) -> None:
        expired = [sid for sid, s in self._sessions.items() if s.is_expired()]
        for sid in expired:
            del self._sessions[sid]
            log.debug("Session TTL evicted", session_id=sid)


# ── Singleton ─────────────────────────────────────────────────────────────────
_store: Optional[SessionStore] = None


def get_session_store() -> SessionStore:
    global _store
    if _store is None:
        _store = SessionStore()
    return _store

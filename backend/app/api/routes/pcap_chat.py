"""
PCAP Chat API Routes
====================
POST /pcap/upload              Upload a PCAP file; returns session_id + analysis summary
POST /pcap/{session_id}/chat   Ask a natural-language question; returns LLM answer + sources
GET  /pcap/{session_id}        Get session summary (metadata)
GET  /pcap/{session_id}/history  Full chat history
GET  /pcap/{session_id}/questions  Suggested questions based on the capture content
DELETE /pcap/{session_id}      Drop an in-memory session early
GET  /pcap/sessions            List all live sessions
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas_pcap import (
    ChatHistoryResponse,
    ChatRequest,
    ChatResponse,
    SessionSummaryResponse,
    SuggestedQuestions,
    UploadResponse,
)
from app.config import get_settings
from app.database import get_db
from app.llm.explanation_engine import create_provider
from app.logger import get_logger
from app.models.pcap_session import PcapSession
from app.pcap.pcap_processor import PcapProcessor
from app.pcap.rag_engine import RAGEngine
from app.pcap.session_store import ChatMessage, PcapChatSession, get_session_store

router = APIRouter(prefix="/pcap", tags=["pcap-chat"])
log = get_logger(__name__)
settings = get_settings()

_MAX_UPLOAD_BYTES = 200 * 1024 * 1024   # 200 MB hard cap
_ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


# ── Upload ─────────────────────────────────────────────────────────────────────

@router.post("/upload", response_model=UploadResponse)
async def upload_pcap(
    file: Annotated[UploadFile, File(description="PCAP / PCAPng file (max 200 MB)")],
    db: AsyncSession = Depends(get_db),
) -> UploadResponse:
    # ── Validate ──────────────────────────────────────────────────────────────
    suffix = Path(file.filename or "x.pcap").suffix.lower()
    if suffix not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Allowed: {_ALLOWED_EXTENSIONS}",
        )

    raw = await file.read()
    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds 200 MB limit")
    if len(raw) < 24:
        raise HTTPException(status_code=400, detail="File is too small to be a valid PCAP")

    # ── Save to temp file ────────────────────────────────────────────────────
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(raw)
        tmp_path = Path(tmp.name)

    # ── Process PCAP (blocking — run in thread) ───────────────────────────────
    loop = asyncio.get_running_loop()
    processor = PcapProcessor()
    filename = file.filename or "upload.pcap"
    analysis = await loop.run_in_executor(None, processor.process, tmp_path, filename)

    try:
        tmp_path.unlink(missing_ok=True)
    except OSError:
        pass

    if analysis.error and analysis.total_packets == 0:
        raise HTTPException(status_code=422, detail=f"PCAP parse error: {analysis.error}")

    # ── Build RAG engine ──────────────────────────────────────────────────────
    provider = create_provider()
    engine = RAGEngine(analysis, provider)

    # Attempt dense embedding index (Ollama) — silently falls back to TF-IDF
    embedding_ok = False
    if settings.llm_provider == "ollama":
        embedding_ok = await engine.build_embedding_index(
            ollama_url=settings.ollama_base_url,
            model=settings.llm_model,
        )

    # ── Build and persist session ─────────────────────────────────────────────
    store = get_session_store()
    session_id = store.new_id()
    session = PcapChatSession(
        session_id=session_id,
        filename=filename,
        analysis=analysis,
        engine=engine,
    )
    await store.put(session)

    # ── Persist metadata to DB ────────────────────────────────────────────────
    n_anomalies = len([a for a in analysis.anomaly_results if a.get("is_anomaly")])
    db_row = PcapSession(
        session_id=session_id,
        filename=filename,
        file_size_bytes=len(raw),
        total_packets=analysis.total_packets,
        total_flows=analysis.total_flows,
        total_anomalies=n_anomalies,
        duration_seconds=analysis.duration_seconds,
        chunk_count=len(analysis.chunks),
        llm_provider=settings.llm_provider,
        error=analysis.error,
    )
    db.add(db_row)
    await db.flush()

    log.info(
        "PCAP session created",
        session_id=session_id,
        filename=filename,
        packets=analysis.total_packets,
        flows=analysis.total_flows,
        chunks=len(analysis.chunks),
        embeddings=embedding_ok,
    )

    return UploadResponse(
        session_id=session_id,
        filename=filename,
        total_packets=analysis.total_packets,
        total_flows=analysis.total_flows,
        total_anomalies=n_anomalies,
        duration_seconds=analysis.duration_seconds,
        chunk_count=len(analysis.chunks),
        protocol_counts=analysis.protocol_counts,
        top_talkers=analysis.top_talkers[:5],
        dns_query_count=len(analysis.dns_queries),
        llm_provider=settings.llm_provider,
        embedding_index=embedding_ok,
        error=analysis.error,
    )


# ── Chat ───────────────────────────────────────────────────────────────────────

@router.post("/{session_id}/chat", response_model=ChatResponse)
async def chat(
    session_id: str,
    req: ChatRequest,
    db: AsyncSession = Depends(get_db),
) -> ChatResponse:
    store = get_session_store()
    session = await store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    async with session.lock:
        # Append user message
        session.history.append(ChatMessage(role="user", content=req.question))

        # RAG answer
        answer, sources = await session.engine.answer(req.question)

        # Append assistant message
        source_dicts = [
            {"category": s.chunk.category, "content": s.chunk.content[:300],
             "score": round(s.score, 4), "metadata": s.chunk.metadata}
            for s in sources
        ]
        session.history.append(ChatMessage(
            role="assistant", content=answer, sources=source_dicts
        ))
        msg_index = len(session.history) - 1

    # Update DB message count
    result = await db.execute(
        select(PcapSession).where(PcapSession.session_id == session_id)
    )
    db_row = result.scalar_one_or_none()
    if db_row:
        db_row.message_count = len(session.history)
        db_row.last_active_at = __import__("datetime").datetime.utcnow()
        await db.flush()

    return ChatResponse(
        session_id=session_id,
        question=req.question,
        answer=answer,
        sources=[
            {"category": s.chunk.category, "content": s.chunk.content[:300],
             "score": round(s.score, 4), "metadata": s.chunk.metadata}
            for s in sources
        ],
        message_index=msg_index,
    )


# ── Session info ───────────────────────────────────────────────────────────────

@router.get("/{session_id}", response_model=SessionSummaryResponse)
async def get_session(session_id: str) -> SessionSummaryResponse:
    store = get_session_store()
    session = await store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    return SessionSummaryResponse(**session.summary_dict())


@router.get("/{session_id}/history", response_model=ChatHistoryResponse)
async def get_history(session_id: str) -> ChatHistoryResponse:
    store = get_session_store()
    session = await store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    messages = [
        {"role": m.role, "content": m.content,
         "sources": m.sources, "timestamp": m.timestamp}
        for m in session.history
    ]
    return ChatHistoryResponse(
        session_id=session_id,
        filename=session.filename,
        messages=messages,
    )


@router.get("/{session_id}/questions", response_model=SuggestedQuestions)
async def suggested_questions(session_id: str) -> SuggestedQuestions:
    """Return context-aware suggested questions based on what is in the capture."""
    store = get_session_store()
    session = await store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    analysis = session.analysis
    questions = _build_suggested_questions(analysis)
    return SuggestedQuestions(session_id=session_id, questions=questions)


@router.delete("/{session_id}")
async def delete_session(session_id: str) -> dict:
    store = get_session_store()
    await store.delete(session_id)
    return {"status": "deleted", "session_id": session_id}


@router.get("/sessions/list")
async def list_sessions() -> dict:
    store = get_session_store()
    sessions = await store.list_sessions()
    return {"sessions": sessions, "count": len(sessions)}


# ── Suggested questions builder ────────────────────────────────────────────────

def _build_suggested_questions(analysis) -> list[str]:
    questions = [
        "Give me a high-level summary of what happened in this capture.",
        "Which hosts transferred the most data?",
    ]

    n_anomalies = len([a for a in analysis.anomaly_results if a.get("is_anomaly")])
    if n_anomalies > 0:
        questions.append("Were any anomalies detected? What types and how severe?")
        questions.append("Which flows were flagged as suspicious and why?")

    if analysis.dns_queries:
        questions.append(f"What DNS queries were made? Were any domains unusual?")

    if any(p in analysis.protocol_counts for p in ("TCP", "HTTP", "HTTPS")):
        questions.append("Were there any TCP handshake failures or connection issues?")
        questions.append("Explain the TCP connection patterns in this capture.")

    by_type = {}
    for a in analysis.anomaly_results:
        if a.get("is_anomaly") and a.get("anomaly_type"):
            by_type[a["anomaly_type"]] = by_type.get(a["anomaly_type"], 0) + 1
    if "port_scan" in by_type:
        questions.append("Was there a port scan? Which host performed it and what ports were probed?")
    if "dns_spike" in by_type:
        questions.append("There seems to be a DNS spike — what caused it?")
    if "data_exfiltration" in by_type:
        questions.append("Is there evidence of data exfiltration in this capture?")

    if analysis.http_events:
        questions.append("What HTTP hosts and endpoints were accessed?")

    questions.append("Which protocols were used and in what proportion?")
    questions.append("Were there any signs of retransmissions or packet loss?")

    return questions[:10]

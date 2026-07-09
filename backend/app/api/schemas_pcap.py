from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class UploadResponse(BaseModel):
    session_id: str
    filename: str
    total_packets: int
    total_flows: int
    total_anomalies: int
    duration_seconds: float
    chunk_count: int
    protocol_counts: dict[str, int]
    top_talkers: list[dict[str, Any]]
    dns_query_count: int
    llm_provider: str
    embedding_index: bool
    error: Optional[str] = None


class ChatRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000)


class SourceChunk(BaseModel):
    category: str
    content: str
    score: float
    metadata: dict[str, Any]


class ChatResponse(BaseModel):
    session_id: str
    question: str
    answer: str
    sources: list[SourceChunk]
    message_index: int


class ChatHistoryResponse(BaseModel):
    session_id: str
    filename: str
    messages: list[dict[str, Any]]


class SessionSummaryResponse(BaseModel):
    session_id: str
    filename: str
    total_packets: int
    total_flows: int
    total_anomalies: int
    duration_seconds: float
    chunk_count: int
    protocol_counts: dict[str, int]
    top_talkers: list[dict[str, Any]]
    dns_query_count: int
    created_at: float
    message_count: int
    error: Optional[str] = None


class SuggestedQuestions(BaseModel):
    session_id: str
    questions: list[str]

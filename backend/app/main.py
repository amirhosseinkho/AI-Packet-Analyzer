from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.api.routes import anomalies, flows, insights, packets, pcap_chat, reports, statistics
from app.api.websocket import router as ws_router
from app.config import get_settings
from app.database.connection import close_db, init_db
from app.logger import configure_logging, get_logger

settings = get_settings()
configure_logging(settings.log_level)
log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    log.info("Starting AI Packet Analyzer", env=settings.app_env)
    await init_db()
    log.info("Database initialised")
    yield
    log.info("Shutting down")
    await close_db()


app = FastAPI(
    title="AI Packet Analyzer",
    description="Wireshark-inspired AI-powered network traffic analyzer",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ── Middleware ────────────────────────────────────────────────────────────────
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ───────────────────────────────────────────────────────────────────
API_PREFIX = "/api/v1"
app.include_router(packets.router, prefix=API_PREFIX)
app.include_router(flows.router, prefix=API_PREFIX)
app.include_router(anomalies.router, prefix=API_PREFIX)
app.include_router(insights.router, prefix=API_PREFIX)
app.include_router(statistics.router, prefix=API_PREFIX)
app.include_router(reports.router, prefix=API_PREFIX)
app.include_router(pcap_chat.router, prefix=API_PREFIX)
app.include_router(ws_router)


@app.get("/health", tags=["health"])
async def health_check() -> dict[str, str]:
    return {"status": "ok", "version": "1.0.0"}

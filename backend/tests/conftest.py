from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database.connection import Base, get_db
from app.main import app

TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def engine():
    _engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield _engine
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await _engine.dispose()


@pytest_asyncio.fixture
async def db_session(engine) -> AsyncGenerator[AsyncSession, None]:
    Session = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    async with Session() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    async def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


# ── Factories ─────────────────────────────────────────────────────────────────

def make_flow_stats(**kwargs):
    from app.flow.statistics import FlowStatistics

    defaults = dict(
        flow_id="abc123",
        src_ip="192.168.1.1",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=443,
        protocol="TCP",
        packet_count=100,
        byte_count=150_000,
        duration_seconds=10.0,
        packets_per_second=10.0,
        bytes_per_second=15_000.0,
        avg_packet_size=1500.0,
        tcp_syn_count=1,
        tcp_fin_count=1,
        tcp_rst_count=0,
        tcp_ack_count=98,
        tcp_psh_count=50,
        start_time=datetime.now(tz=timezone.utc),
    )
    defaults.update(kwargs)
    return FlowStatistics(**defaults)

from __future__ import annotations

import io
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient


def _make_pcap_bytes() -> bytes:
    """Smallest possible valid PCAP (header only, 0 packets)."""
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _make_fake_analysis():
    from tests.test_pcap.fixtures import make_analysis
    return make_analysis(n_flows=3, n_anomalies=1)


@pytest.mark.asyncio
class TestPcapUpload:
    async def test_upload_wrong_extension_rejected(self, client: AsyncClient):
        r = await client.post(
            "/api/v1/pcap/upload",
            files={"file": ("bad.exe", b"notapcap", "application/octet-stream")},
        )
        assert r.status_code == 400
        assert "Unsupported file type" in r.json()["detail"]

    async def test_upload_too_small_rejected(self, client: AsyncClient):
        r = await client.post(
            "/api/v1/pcap/upload",
            files={"file": ("tiny.pcap", b"\x00" * 10, "application/octet-stream")},
        )
        assert r.status_code == 400
        assert "too small" in r.json()["detail"].lower()

    async def test_upload_valid_pcap(self, client: AsyncClient):
        fake_analysis = _make_fake_analysis()

        with (
            patch("app.api.routes.pcap_chat.PcapProcessor") as MockProcessor,
            patch("app.api.routes.pcap_chat.RAGEngine") as MockEngine,
        ):
            instance = MagicMock()
            instance.process.return_value = fake_analysis
            MockProcessor.return_value = instance

            engine_instance = MagicMock()
            engine_instance.build_embedding_index = AsyncMock(return_value=False)
            MockEngine.return_value = engine_instance

            r = await client.post(
                "/api/v1/pcap/upload",
                files={"file": ("test.pcap", _make_pcap_bytes(), "application/octet-stream")},
            )

        assert r.status_code == 200
        data = r.json()
        assert "session_id" in data
        assert data["filename"] == "test.pcap"
        assert "total_packets" in data
        assert "chunk_count" in data

    async def test_upload_returns_session_id(self, client: AsyncClient):
        fake_analysis = _make_fake_analysis()

        with (
            patch("app.api.routes.pcap_chat.PcapProcessor") as MockProcessor,
            patch("app.api.routes.pcap_chat.RAGEngine") as MockEngine,
        ):
            instance = MagicMock()
            instance.process.return_value = fake_analysis
            MockProcessor.return_value = instance

            engine_instance = MagicMock()
            engine_instance.build_embedding_index = AsyncMock(return_value=False)
            MockEngine.return_value = engine_instance

            r = await client.post(
                "/api/v1/pcap/upload",
                files={"file": ("capture.pcap", _make_pcap_bytes(), "application/octet-stream")},
            )

        assert r.status_code == 200
        session_id = r.json()["session_id"]
        assert len(session_id) == 36  # UUID format


@pytest.mark.asyncio
class TestPcapChat:
    async def _create_session(self, client: AsyncClient) -> str:
        fake_analysis = _make_fake_analysis()
        with (
            patch("app.api.routes.pcap_chat.PcapProcessor") as MockProc,
            patch("app.api.routes.pcap_chat.RAGEngine") as MockEng,
        ):
            MockProc.return_value.process.return_value = fake_analysis
            eng = MagicMock()
            eng.build_embedding_index = AsyncMock(return_value=False)
            MockEng.return_value = eng

            r = await client.post(
                "/api/v1/pcap/upload",
                files={"file": ("t.pcap", _make_pcap_bytes(), "application/octet-stream")},
            )
        return r.json()["session_id"]

    async def test_chat_session_not_found(self, client: AsyncClient):
        r = await client.post(
            "/api/v1/pcap/nonexistent-session-id/chat",
            json={"question": "What happened?"},
        )
        assert r.status_code == 404

    async def test_chat_empty_question_rejected(self, client: AsyncClient):
        r = await client.post(
            "/api/v1/pcap/some-session/chat",
            json={"question": ""},
        )
        assert r.status_code == 422  # pydantic validation

    async def test_chat_returns_answer(self, client: AsyncClient):
        session_id = await self._create_session(client)

        from app.pcap.session_store import get_session_store
        from tests.test_pcap.fixtures import make_analysis
        from app.pcap.rag_engine import RAGEngine
        from app.llm.providers.mock_provider import MockProvider

        store = get_session_store()
        session = await store.get(session_id)
        if session:
            # Replace engine with a real one backed by MockProvider
            session.engine = RAGEngine(make_analysis(), MockProvider())

        r = await client.post(
            f"/api/v1/pcap/{session_id}/chat",
            json={"question": "What happened in this capture?"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "answer" in data
        assert "sources" in data
        assert "question" in data
        assert data["question"] == "What happened in this capture?"

    async def test_get_history_empty(self, client: AsyncClient):
        session_id = await self._create_session(client)
        r = await client.get(f"/api/v1/pcap/{session_id}/history")
        assert r.status_code == 200
        data = r.json()
        assert "messages" in data
        assert isinstance(data["messages"], list)

    async def test_get_summary(self, client: AsyncClient):
        session_id = await self._create_session(client)
        r = await client.get(f"/api/v1/pcap/{session_id}")
        assert r.status_code == 200
        data = r.json()
        assert data["session_id"] == session_id
        assert "total_packets" in data

    async def test_get_suggested_questions(self, client: AsyncClient):
        session_id = await self._create_session(client)
        r = await client.get(f"/api/v1/pcap/{session_id}/questions")
        assert r.status_code == 200
        data = r.json()
        assert "questions" in data
        assert isinstance(data["questions"], list)
        assert len(data["questions"]) > 0

    async def test_delete_session(self, client: AsyncClient):
        session_id = await self._create_session(client)
        r = await client.delete(f"/api/v1/pcap/{session_id}")
        assert r.status_code == 200
        # Subsequent get should 404
        r2 = await client.get(f"/api/v1/pcap/{session_id}")
        assert r2.status_code == 404

    async def test_list_sessions(self, client: AsyncClient):
        r = await client.get("/api/v1/pcap/sessions/list")
        assert r.status_code == 200
        assert "sessions" in r.json()


@pytest.mark.asyncio
class TestSessionStore:
    async def test_put_and_get(self):
        from app.pcap.session_store import PcapChatSession, SessionStore
        from tests.test_pcap.fixtures import make_analysis
        from app.pcap.rag_engine import RAGEngine
        from app.llm.providers.mock_provider import MockProvider

        store = SessionStore()
        analysis = make_analysis()
        engine = RAGEngine(analysis, MockProvider())
        session = PcapChatSession(
            session_id="test-abc",
            filename="x.pcap",
            analysis=analysis,
            engine=engine,
        )
        await store.put(session)
        retrieved = await store.get("test-abc")
        assert retrieved is not None
        assert retrieved.session_id == "test-abc"

    async def test_get_nonexistent_returns_none(self):
        from app.pcap.session_store import SessionStore
        store = SessionStore()
        assert await store.get("does-not-exist") is None

    async def test_delete_removes_session(self):
        from app.pcap.session_store import PcapChatSession, SessionStore
        from tests.test_pcap.fixtures import make_analysis
        from app.pcap.rag_engine import RAGEngine
        from app.llm.providers.mock_provider import MockProvider

        store = SessionStore()
        analysis = make_analysis()
        engine = RAGEngine(analysis, MockProvider())
        session = PcapChatSession(
            session_id="to-delete",
            filename="y.pcap",
            analysis=analysis,
            engine=engine,
        )
        await store.put(session)
        await store.delete("to-delete")
        assert await store.get("to-delete") is None

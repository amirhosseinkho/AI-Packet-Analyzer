from __future__ import annotations

import pytest

from app.llm.explanation_engine import ExplanationEngine, _fallback_explanation
from app.llm.providers.mock_provider import MockProvider


@pytest.mark.asyncio
class TestMockProvider:
    async def test_complete_returns_string(self):
        provider = MockProvider()
        result = await provider.complete("test prompt")
        assert isinstance(result, str)
        assert len(result) > 0

    async def test_health_check(self):
        provider = MockProvider()
        assert await provider.health_check() is True


@pytest.mark.asyncio
class TestExplanationEngine:
    async def test_explain_flow_normal(self):
        from tests.conftest import make_flow_stats

        engine = ExplanationEngine(MockProvider())
        flow = make_flow_stats()
        explanation = await engine.explain_flow(flow, None)
        assert isinstance(explanation, str)
        assert len(explanation) > 0

    async def test_explain_flow_anomaly(self):
        from tests.conftest import make_flow_stats

        engine = ExplanationEngine(MockProvider())
        flow = make_flow_stats()
        anomaly = {"is_anomaly": True, "anomaly_type": "port_scan", "ensemble_score": 0.9}
        explanation = await engine.explain_flow(flow, anomaly)
        assert isinstance(explanation, str)

    async def test_explain_batch(self):
        from tests.conftest import make_flow_stats

        engine = ExplanationEngine(MockProvider())
        flows = [make_flow_stats(flow_id=f"flow{i}") for i in range(3)]
        results = await engine.explain_batch(flows)
        assert len(results) == 3
        for flow in flows:
            assert flow.flow_id in results


class TestFallbackExplanation:
    def test_fallback_normal(self):
        from tests.conftest import make_flow_stats

        flow = make_flow_stats()
        text = _fallback_explanation(flow, None)
        assert "TCP" in text or flow.src_ip in text

    def test_fallback_anomaly(self):
        from tests.conftest import make_flow_stats

        flow = make_flow_stats()
        anomaly = {"is_anomaly": True, "anomaly_type": "port_scan", "ensemble_score": 0.9}
        text = _fallback_explanation(flow, anomaly)
        assert "port_scan" in text or "Anomalous" in text

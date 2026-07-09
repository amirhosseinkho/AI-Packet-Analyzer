from __future__ import annotations

import json
from typing import Optional

from app.config import get_settings
from app.flow.statistics import FlowStatistics
from app.llm.providers.base import BaseLLMProvider
from app.logger import get_logger

log = get_logger(__name__)
settings = get_settings()

_SYSTEM_PROMPT = """You are a senior network security analyst AI assistant.
Given network flow statistics and anomaly detection results, provide a concise,
human-readable explanation of the traffic behavior.

Focus on:
- What type of traffic this likely represents
- Whether any security concern exists
- Actionable recommendations if anomalous

Respond in 1-3 sentences. Be specific and technical but understandable.
Do NOT include JSON or code in your response."""


def _build_prompt(flow: FlowStatistics, anomaly_result: Optional[dict]) -> str:
    flow_summary = {
        "flow_id": flow.flow_id,
        "src": f"{flow.src_ip}:{flow.src_port or '*'}",
        "dst": f"{flow.dst_ip}:{flow.dst_port or '*'}",
        "protocol": flow.protocol,
        "packet_count": flow.packet_count,
        "byte_count": flow.byte_count,
        "duration_seconds": round(flow.duration_seconds or 0, 3),
        "avg_packet_size": round(flow.avg_packet_size or 0, 1),
        "packets_per_second": round(flow.packets_per_second or 0, 2),
        "bytes_per_second": round(flow.bytes_per_second or 0, 2),
        "tcp_flags": {
            "SYN": flow.tcp_syn_count,
            "FIN": flow.tcp_fin_count,
            "RST": flow.tcp_rst_count,
            "ACK": flow.tcp_ack_count,
            "PSH": flow.tcp_psh_count,
        },
    }
    anomaly_summary = anomaly_result or {"is_anomaly": False}
    return (
        f"Network flow statistics:\n{json.dumps(flow_summary, indent=2)}\n\n"
        f"Anomaly detection result:\n{json.dumps(anomaly_summary, indent=2)}\n\n"
        "Explain this network flow in plain English."
    )


class ExplanationEngine:
    """Generates natural-language explanations of network flows using an LLM."""

    def __init__(self, provider: BaseLLMProvider) -> None:
        self._provider = provider

    async def explain_flow(
        self,
        flow: FlowStatistics,
        anomaly_result: Optional[dict] = None,
    ) -> str:
        prompt = _build_prompt(flow, anomaly_result)
        try:
            explanation = await self._provider.complete(
                prompt=prompt,
                system=_SYSTEM_PROMPT,
                temperature=settings.llm_temperature,
                max_tokens=settings.llm_max_tokens,
            )
            return explanation
        except Exception as exc:
            log.error("LLM explanation failed", flow_id=flow.flow_id, error=str(exc))
            return _fallback_explanation(flow, anomaly_result)

    async def explain_batch(
        self,
        flows: list[FlowStatistics],
        anomaly_results: Optional[dict[str, dict]] = None,
    ) -> dict[str, str]:
        explanations: dict[str, str] = {}
        for flow in flows:
            anomaly = (anomaly_results or {}).get(flow.flow_id)
            explanations[flow.flow_id] = await self.explain_flow(flow, anomaly)
        return explanations

    async def health(self) -> bool:
        return await self._provider.health_check()


def _fallback_explanation(flow: FlowStatistics, anomaly: Optional[dict]) -> str:
    if anomaly and anomaly.get("is_anomaly"):
        atype = anomaly.get("anomaly_type", "unknown")
        score = anomaly.get("ensemble_score", 0)
        return (
            f"Anomalous {flow.protocol} flow detected (type: {atype}, score: {score:.2f}). "
            f"{flow.packet_count} packets, {flow.byte_count} bytes from {flow.src_ip} to {flow.dst_ip}."
        )
    return (
        f"Normal {flow.protocol} traffic from {flow.src_ip} to {flow.dst_ip}. "
        f"{flow.packet_count} packets, {flow.byte_count} bytes over {round(flow.duration_seconds or 0, 1)}s."
    )


# ── Factory ───────────────────────────────────────────────────────────────────

def create_provider(provider_name: Optional[str] = None) -> BaseLLMProvider:
    name = provider_name or settings.llm_provider
    if name == "ollama":
        from app.llm.providers.ollama_provider import OllamaProvider
        return OllamaProvider()
    if name == "openai":
        from app.llm.providers.openai_provider import OpenAIProvider
        return OpenAIProvider()
    if name == "mock":
        from app.llm.providers.mock_provider import MockProvider
        return MockProvider()
    raise ValueError(f"Unknown LLM provider: {name!r}")


_engine: Optional[ExplanationEngine] = None


def get_explanation_engine() -> ExplanationEngine:
    global _engine
    if _engine is None:
        _engine = ExplanationEngine(create_provider())
    return _engine

from __future__ import annotations

from typing import Optional

import numpy as np

from app.ai.autoencoder import AutoencoderDetector
from app.ai.feature_extractor import FeatureExtractor
from app.ai.isolation_forest import IsolationForestDetector
from app.flow.statistics import FlowStatistics
from app.logger import get_logger

log = get_logger(__name__)

_SEVERITY_THRESHOLDS = {
    "low": 0.4,
    "medium": 0.6,
    "high": 0.8,
    "critical": 0.95,
}


def _score_to_severity(score: float) -> str:
    for severity in ("critical", "high", "medium", "low"):
        if score >= _SEVERITY_THRESHOLDS[severity]:
            return severity
    return "info"


class AnomalyDetectorService:
    """Ensemble anomaly detector combining IsolationForest and Autoencoder."""

    def __init__(self) -> None:
        self._extractor = FeatureExtractor()
        self._if = IsolationForestDetector.load_or_create()
        self._ae = AutoencoderDetector.load_or_create()
        self._trained = self._if._trained and self._ae._trained

    def train(self, flows: list[FlowStatistics]) -> None:
        if len(flows) < 10:
            log.warning("Not enough flows to train", n=len(flows))
            return
        X = self._extractor.fit_transform(flows)
        self._if.fit(X)
        self._ae.fit(X)
        self._trained = True
        self._if.save()
        self._ae.save()

    def analyse(self, flows: list[FlowStatistics]) -> list[dict]:
        """Score each flow and return enriched anomaly results."""
        if not flows:
            return []

        X = self._extractor.transform(flows)
        if_results = {r["flow_id"]: r for r in self._if.score_flows(flows, X)} if self._if._trained else {}
        ae_results = {r["flow_id"]: r for r in self._ae.score_flows(flows, X)} if self._ae._trained else {}

        combined = []
        for flow in flows:
            fid = flow.flow_id
            if_r = if_results.get(fid, {})
            ae_r = ae_results.get(fid, {})

            scores = [s for s in [if_r.get("anomaly_score"), ae_r.get("anomaly_score")] if s is not None]
            ensemble_score = float(np.mean(scores)) if scores else 0.0
            is_anomaly = bool(if_r.get("is_anomaly") or ae_r.get("is_anomaly"))
            anomaly_type = _classify_anomaly(flow) if is_anomaly else None

            combined.append(
                {
                    "flow_id": fid,
                    "if_score": if_r.get("anomaly_score"),
                    "ae_score": ae_r.get("anomaly_score"),
                    "ensemble_score": ensemble_score,
                    "is_anomaly": is_anomaly,
                    "anomaly_type": anomaly_type,
                    "severity": _score_to_severity(ensemble_score) if is_anomaly else "info",
                }
            )

        return combined


def _classify_anomaly(flow: FlowStatistics) -> Optional[str]:
    """Heuristic anomaly classifier based on flow features."""
    # Port scan: many SYN, few ACK, short duration
    if flow.tcp_syn_count > 20 and flow.tcp_ack_count < 5 and (flow.duration_seconds or 0) < 5:
        return "port_scan"

    # DNS spike
    if flow.protocol == "DNS" and flow.packet_count > 100:
        return "dns_spike"

    # High volume data exfiltration hint
    if flow.byte_count > 50_000_000 and flow.protocol in ("TCP", "HTTPS"):
        return "data_exfiltration"

    # RST storm
    if flow.tcp_rst_count > 50:
        return "rst_storm"

    # Slow loris / many small packets
    if flow.packet_count > 500 and (flow.avg_packet_size or 0) < 100:
        return "slow_loris"

    return "unknown"


# ── Singleton ─────────────────────────────────────────────────────────────────
_detector: Optional[AnomalyDetectorService] = None


def get_detector() -> AnomalyDetectorService:
    global _detector
    if _detector is None:
        _detector = AnomalyDetectorService()
    return _detector

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest as SKLearnIF

from app.config import get_settings
from app.flow.statistics import FlowStatistics
from app.logger import get_logger

log = get_logger(__name__)
settings = get_settings()

_MODEL_FILE = settings.model_save_path / "isolation_forest.pkl"


class IsolationForestDetector:
    """Anomaly detector based on scikit-learn IsolationForest."""

    NAME = "isolation_forest"

    def __init__(self, contamination: float = 0.05) -> None:
        self._model = SKLearnIF(
            contamination=contamination,
            n_estimators=200,
            random_state=42,
            n_jobs=-1,
        )
        self._trained = False

    def fit(self, X: np.ndarray) -> None:
        self._model.fit(X)
        self._trained = True
        log.info("IsolationForest trained", samples=len(X))

    def predict(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Returns (labels, scores).

        labels: 1 = normal, -1 = anomaly  (sklearn convention)
        scores: raw decision function values (more negative = more anomalous)
        """
        if not self._trained:
            raise RuntimeError("Model not trained. Call fit() first.")
        labels = self._model.predict(X)
        scores = self._model.decision_function(X)
        return labels, scores

    def score_flows(self, flows: list[FlowStatistics], X: np.ndarray) -> list[dict]:
        labels, scores = self.predict(X)
        results = []
        for flow, label, score in zip(flows, labels, scores):
            # Normalise score to [0, 1] where 1 = most anomalous
            normalised = float(np.clip((score * -1 + 0.5), 0, 1))
            results.append(
                {
                    "flow_id": flow.flow_id,
                    "detector": self.NAME,
                    "anomaly_score": normalised,
                    "is_anomaly": bool(label == -1),
                    "raw_score": float(score),
                }
            )
        return results

    # ── Persistence ────────────────────────────────────────────────────────────

    def save(self, path: Optional[Path] = None) -> None:
        target = path or _MODEL_FILE
        with open(target, "wb") as f:
            pickle.dump(self._model, f)
        log.info("IsolationForest saved", path=str(target))

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "IsolationForestDetector":
        target = path or _MODEL_FILE
        instance = cls()
        with open(target, "rb") as f:
            instance._model = pickle.load(f)
        instance._trained = True
        log.info("IsolationForest loaded", path=str(target))
        return instance

    @classmethod
    def load_or_create(cls) -> "IsolationForestDetector":
        if _MODEL_FILE.exists():
            return cls.load()
        return cls(contamination=settings.isolation_forest_contamination)

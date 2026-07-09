from __future__ import annotations

import numpy as np
from sklearn.preprocessing import StandardScaler

from app.flow.statistics import FlowStatistics


class FeatureExtractor:
    """Transforms FlowStatistics objects into normalised numpy feature matrices."""

    def __init__(self) -> None:
        self._scaler = StandardScaler()
        self._fitted = False

    @property
    def feature_names(self) -> list[str]:
        return FlowStatistics.__fields_set__ and FlowStatistics(
            flow_id="x", src_ip="0", dst_ip="0", protocol="TCP"
        ).feature_names

    def fit(self, flows: list[FlowStatistics]) -> "FeatureExtractor":
        X = self._to_matrix(flows)
        self._scaler.fit(X)
        self._fitted = True
        return self

    def transform(self, flows: list[FlowStatistics]) -> np.ndarray:
        X = self._to_matrix(flows)
        if self._fitted:
            return self._scaler.transform(X)
        return X

    def fit_transform(self, flows: list[FlowStatistics]) -> np.ndarray:
        X = self._to_matrix(flows)
        self._scaler.fit(X)
        self._fitted = True
        return self._scaler.transform(X)

    @staticmethod
    def _to_matrix(flows: list[FlowStatistics]) -> np.ndarray:
        return np.array([f.to_feature_vector() for f in flows], dtype=np.float32)

from __future__ import annotations

import numpy as np
import pytest

from app.ai.autoencoder import AutoencoderDetector
from app.ai.feature_extractor import FeatureExtractor
from app.ai.isolation_forest import IsolationForestDetector


def _make_normal_data(n: int = 100) -> np.ndarray:
    rng = np.random.default_rng(42)
    return rng.normal(loc=0.5, scale=0.1, size=(n, 13)).astype(np.float32)


def _make_anomalous_data(n: int = 5) -> np.ndarray:
    rng = np.random.default_rng(99)
    return rng.normal(loc=5.0, scale=1.0, size=(n, 13)).astype(np.float32)


class TestIsolationForest:
    def test_fit_predict(self):
        X_train = _make_normal_data(200)
        X_anomaly = _make_anomalous_data(10)

        detector = IsolationForestDetector(contamination=0.05)
        detector.fit(X_train)

        labels, scores = detector.predict(X_anomaly)
        assert len(labels) == 10
        assert len(scores) == 10
        # Expect at least some anomalies detected in clearly anomalous data
        assert any(l == -1 for l in labels)

    def test_not_trained_raises(self):
        detector = IsolationForestDetector()
        X = _make_normal_data(10)
        with pytest.raises(RuntimeError, match="not trained"):
            detector.predict(X)

    def test_score_flows(self, tmp_path):
        from tests.conftest import make_flow_stats

        flows = [make_flow_stats(flow_id=f"flow{i}") for i in range(10)]
        X = _make_normal_data(10)
        detector = IsolationForestDetector()
        detector.fit(X)
        results = detector.score_flows(flows, X)
        assert len(results) == 10
        for r in results:
            assert 0.0 <= r["anomaly_score"] <= 1.0
            assert "flow_id" in r
            assert "is_anomaly" in r


class TestAutoencoder:
    def test_fit_predict(self):
        X_train = _make_normal_data(100)
        X_test = _make_normal_data(10)

        detector = AutoencoderDetector(epochs=5, batch_size=16)
        detector.fit(X_train)
        labels, errors = detector.predict(X_test)

        assert len(labels) == 10
        assert all(e >= 0 for e in errors)

    def test_anomaly_has_higher_reconstruction_error(self):
        X_train = _make_normal_data(200)
        X_normal = _make_normal_data(5)
        X_anomaly = _make_anomalous_data(5)

        detector = AutoencoderDetector(epochs=20, batch_size=32)
        detector.fit(X_train)

        _, err_normal = detector.predict(X_normal)
        _, err_anomaly = detector.predict(X_anomaly)

        assert np.mean(err_anomaly) > np.mean(err_normal)

    def test_save_load(self, tmp_path):
        X = _make_normal_data(50)
        detector = AutoencoderDetector(epochs=3, batch_size=16)
        detector.fit(X)
        path = tmp_path / "ae.pt"
        detector.save(path)
        loaded = AutoencoderDetector.load(path)
        assert loaded._trained
        _, errors = loaded.predict(X)
        assert len(errors) == 50


class TestFeatureExtractor:
    def test_fit_transform(self):
        from tests.conftest import make_flow_stats

        flows = [make_flow_stats(flow_id=str(i)) for i in range(20)]
        extractor = FeatureExtractor()
        X = extractor.fit_transform(flows)
        assert X.shape == (20, 13)
        assert extractor._fitted

    def test_transform_without_fit_returns_raw(self):
        from tests.conftest import make_flow_stats

        flows = [make_flow_stats(flow_id=str(i)) for i in range(5)]
        extractor = FeatureExtractor()
        X = extractor.transform(flows)
        assert X.shape == (5, 13)

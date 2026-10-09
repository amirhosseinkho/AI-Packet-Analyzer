"""Detectors under comparison. Every ``score`` returns higher = more anomalous.

The Isolation Forest and the autoencoder are the application's own classes
(``app.ai``); only their random seed is set here. The ensemble reproduces
``AnomalyDetectorService.analyse`` exactly, including its score normalisation.
"""

from __future__ import annotations

import numpy as np
import torch
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from app.ai.autoencoder import AutoencoderDetector
from app.ai.isolation_forest import IsolationForestDetector


class Detector:
    name = "base"

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.scaler = StandardScaler()  # same preprocessing as app.ai.FeatureExtractor

    def fit(self, X: np.ndarray) -> "Detector":
        self._fit(self.scaler.fit_transform(X))
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        return self._score(self.scaler.transform(X))

    def _fit(self, Z: np.ndarray) -> None:
        raise NotImplementedError

    def _score(self, Z: np.ndarray) -> np.ndarray:
        raise NotImplementedError


class AppIsolationForest(Detector):
    name = "isolation_forest"

    def _fit(self, Z):
        self.model = IsolationForestDetector()
        self.model._model.set_params(random_state=self.seed)
        self.model.fit(Z)

    def _score(self, Z):
        return -self.model._model.decision_function(Z)


class AppAutoencoder(Detector):
    name = "autoencoder"

    def __init__(self, seed: int, epochs: int = 50) -> None:
        super().__init__(seed)
        self.epochs = epochs

    def _fit(self, Z):
        torch.manual_seed(self.seed)
        np.random.seed(self.seed)
        self.model = AutoencoderDetector(input_dim=Z.shape[1], epochs=self.epochs)
        self.model.fit(Z)

    def _score(self, Z):
        return self.model._reconstruction_errors(Z)

    def per_feature_error(self, X: np.ndarray) -> np.ndarray:
        """Squared reconstruction error per feature; its row mean is the anomaly score."""
        Z = self.scaler.transform(X)
        net = self.model._net
        net.eval()
        with torch.no_grad():
            t = torch.tensor(Z, dtype=torch.float32).to(self.model._device)
            return ((t - net(t)) ** 2).cpu().numpy()


class AppEnsemble(Detector):
    """IF + AE combined exactly as AnomalyDetectorService.analyse() does."""

    name = "ensemble"

    def __init__(self, seed: int, epochs: int = 50) -> None:
        super().__init__(seed)
        self.iforest = AppIsolationForest(seed)
        self.autoencoder = AppAutoencoder(seed, epochs)
        self.ae_max: float | None = None  # fixed normaliser for explanation methods

    def fit(self, X):
        self.iforest.fit(X)
        self.autoencoder.fit(X)
        return self

    @classmethod
    def from_parts(cls, iforest: AppIsolationForest, autoencoder: AppAutoencoder) -> "AppEnsemble":
        """Reuse already-trained components instead of training them twice."""
        ens = cls(iforest.seed, autoencoder.epochs)
        ens.iforest, ens.autoencoder = iforest, autoencoder
        return ens

    def components(self, X):
        """(if_score, ae_score) after the app's normalisation."""
        decision = self.iforest.model._model.decision_function(self.iforest.scaler.transform(X))
        if_score = np.clip(-decision + 0.5, 0, 1)
        err = self.autoencoder.score(X)
        # The app divides by the max error of the batch being analysed.
        max_err = self.ae_max if self.ae_max is not None else (float(np.max(err)) or 1.0)
        return if_score, err / max_err

    def score(self, X):
        if_score, ae_score = self.components(X)
        return (if_score + ae_score) / 2

    def deployed_decision(self, X) -> np.ndarray:
        """The app's binary rule: IF says anomaly OR AE error exceeds mean + 3 std."""
        if_labels, _ = self.iforest.model.predict(self.iforest.scaler.transform(X))
        ae_labels, _ = self.autoencoder.model.predict(self.autoencoder.scaler.transform(X))
        return (if_labels == -1) | (ae_labels == -1)


class OCSVM(Detector):
    name = "ocsvm"

    def _fit(self, Z):
        self.model = OneClassSVM(kernel="rbf", gamma="scale", nu=0.01).fit(Z)

    def _score(self, Z):
        return -self.model.decision_function(Z)


class LOF(Detector):
    name = "lof"

    def _fit(self, Z):
        self.model = LocalOutlierFactor(n_neighbors=20, novelty=True, n_jobs=-1).fit(Z)

    def _score(self, Z):
        return -self.model.score_samples(Z)


class ZScoreThreshold(Detector):
    """Simplest baseline: largest absolute z-score over all features."""

    name = "zscore_max"

    def _fit(self, Z):
        pass

    def _score(self, Z):
        return np.abs(Z).max(axis=1)


def build(name: str, seed: int, ae_epochs: int = 50) -> Detector:
    return {
        "isolation_forest": lambda: AppIsolationForest(seed),
        "autoencoder": lambda: AppAutoencoder(seed, ae_epochs),
        "ensemble": lambda: AppEnsemble(seed, ae_epochs),
        "ocsvm": lambda: OCSVM(seed),
        "lof": lambda: LOF(seed),
        "zscore_max": lambda: ZScoreThreshold(seed),
    }[name]()


ALL_MODELS = ["isolation_forest", "autoencoder", "ensemble", "ocsvm", "lof", "zscore_max"]

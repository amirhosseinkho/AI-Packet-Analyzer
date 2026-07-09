from __future__ import annotations

from pathlib import Path
from typing import Optional

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

from app.config import get_settings
from app.flow.statistics import FlowStatistics
from app.logger import get_logger

log = get_logger(__name__)
settings = get_settings()

_MODEL_FILE = settings.model_save_path / "autoencoder.pt"
INPUT_DIM = 13  # must match FlowStatistics.to_feature_vector() length


class _AutoencoderNet(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim * 2),
            nn.ReLU(),
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim * 2),
            nn.ReLU(),
            nn.Linear(hidden_dim * 2, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


class AutoencoderDetector:
    """Anomaly detector using reconstruction error from a PyTorch Autoencoder."""

    NAME = "autoencoder"

    def __init__(
        self,
        input_dim: int = INPUT_DIM,
        hidden_dim: int = 32,
        epochs: int = 50,
        batch_size: int = 64,
        lr: float = 1e-3,
    ) -> None:
        self._input_dim = input_dim
        self._hidden_dim = hidden_dim
        self._epochs = epochs
        self._batch_size = batch_size
        self._lr = lr
        self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._net = _AutoencoderNet(input_dim, hidden_dim).to(self._device)
        self._threshold: float = 0.0
        self._trained = False

    def fit(self, X: np.ndarray) -> None:
        tensor = torch.tensor(X, dtype=torch.float32)
        dataset = TensorDataset(tensor, tensor)
        loader = DataLoader(dataset, batch_size=self._batch_size, shuffle=True)
        optimizer = optim.Adam(self._net.parameters(), lr=self._lr)
        criterion = nn.MSELoss()

        self._net.train()
        for epoch in range(self._epochs):
            epoch_loss = 0.0
            for xb, _ in loader:
                xb = xb.to(self._device)
                optimizer.zero_grad()
                reconstructed = self._net(xb)
                loss = criterion(reconstructed, xb)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item()
            if (epoch + 1) % 10 == 0:
                log.debug("Autoencoder epoch", epoch=epoch + 1, loss=epoch_loss / len(loader))

        # Set threshold as mean + 3*std of reconstruction errors on training data
        errors = self._reconstruction_errors(X)
        self._threshold = float(np.mean(errors) + 3 * np.std(errors))
        self._trained = True
        log.info("Autoencoder trained", samples=len(X), threshold=self._threshold)

    def predict(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        errors = self._reconstruction_errors(X)
        labels = np.where(errors > self._threshold, -1, 1)
        return labels, errors

    def score_flows(self, flows: list[FlowStatistics], X: np.ndarray) -> list[dict]:
        labels, errors = self.predict(X)
        max_err = float(np.max(errors)) or 1.0
        results = []
        for flow, label, err in zip(flows, labels, errors):
            results.append(
                {
                    "flow_id": flow.flow_id,
                    "detector": self.NAME,
                    "anomaly_score": float(err / max_err),
                    "is_anomaly": bool(label == -1),
                    "reconstruction_error": float(err),
                }
            )
        return results

    def _reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        self._net.eval()
        with torch.no_grad():
            tensor = torch.tensor(X, dtype=torch.float32).to(self._device)
            reconstructed = self._net(tensor)
            errors = torch.mean((tensor - reconstructed) ** 2, dim=1)
        return errors.cpu().numpy()

    # ── Persistence ────────────────────────────────────────────────────────────

    def save(self, path: Optional[Path] = None) -> None:
        target = path or _MODEL_FILE
        torch.save(
            {
                "state_dict": self._net.state_dict(),
                "threshold": self._threshold,
                "input_dim": self._input_dim,
                "hidden_dim": self._hidden_dim,
            },
            target,
        )
        log.info("Autoencoder saved", path=str(target))

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "AutoencoderDetector":
        target = path or _MODEL_FILE
        data = torch.load(target, map_location="cpu")
        instance = cls(input_dim=data["input_dim"], hidden_dim=data["hidden_dim"])
        instance._net.load_state_dict(data["state_dict"])
        instance._threshold = data["threshold"]
        instance._trained = True
        log.info("Autoencoder loaded", path=str(target))
        return instance

    @classmethod
    def load_or_create(cls) -> "AutoencoderDetector":
        if _MODEL_FILE.exists():
            return cls.load()
        return cls(
            hidden_dim=settings.autoencoder_hidden_dim,
            epochs=settings.autoencoder_epochs,
            batch_size=settings.autoencoder_batch_size,
        )

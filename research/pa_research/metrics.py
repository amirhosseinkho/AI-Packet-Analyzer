"""Detection metrics. Attacks are the positive class."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from .data import BENIGN


def threshold_at_fpr(val_benign_scores: np.ndarray, fpr: float) -> float:
    """Score threshold calibrated on held-out benign validation flows only.

    No test labels are used, so the realised test FPR is reported alongside.
    """
    return float(np.quantile(val_benign_scores, 1 - fpr))


def detection_metrics(scores: np.ndarray, test: pd.DataFrame, threshold: float) -> tuple[dict, list[dict]]:
    y = test["y"].to_numpy()
    flagged = scores > threshold
    overall = {
        "roc_auc": roc_auc_score(y, scores),
        "pr_auc": average_precision_score(y, scores),
        "attack_prevalence": float(y.mean()),
        "recall_at_fpr": float(flagged[y == 1].mean()),
        "test_fpr": float(flagged[y == 0].mean()),
    }
    benign = (test["attack"] == BENIGN).to_numpy()
    per_attack = []
    for attack in sorted(test.loc[~benign, "attack"].unique()):
        mask = (test["attack"] == attack).to_numpy()
        both = mask | benign
        per_attack.append({
            "attack": attack,
            "n": int(mask.sum()),
            "roc_auc": roc_auc_score(mask[both], scores[both]),
            "recall_at_fpr": float(flagged[mask].mean()),
        })
    return overall, per_attack


def binary_metrics(flagged: np.ndarray, test: pd.DataFrame) -> dict:
    """Operating point of a fixed binary rule (the app's deployed thresholds)."""
    y = test["y"].to_numpy()
    return {"recall": float(flagged[y == 1].mean()), "fpr": float(flagged[y == 0].mean())}

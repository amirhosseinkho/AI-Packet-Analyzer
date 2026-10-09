"""RQ2 helpers: reference attributions and feature mentions in LLM explanations.

Faithfulness is measured as agreement between the features an explanation
names and the features that actually drove the detector's score:

* ``ae_error``: per-feature squared reconstruction error. The autoencoder's
  score is the mean of these terms, so this decomposition is exact.
* ``if_shap``: TreeSHAP values for the Isolation Forest.
* ``ensemble_shap``: KernelSHAP values for the deployed ensemble score.

A *hallucination* is an explanation that relies on information the LLM was
never given (payload, TTL, DNS names, other flows, ...). The lexicons below
are deliberately explicit so they can be audited and extended.
"""

from __future__ import annotations

import re

import numpy as np
import shap

from . import APP_FEATURES
from .models import AppEnsemble

# Phrases that name one of the 13 features shown to the LLM.
FEATURE_PATTERNS: dict[str, str] = {
    "packet_count": r"\bpacket count\b|\bnumber of packets\b|\b\d[\d,]*\s+packets\b(?!\s*(per|/|a second|each second))",
    "byte_count": r"\bbyte count\b|\btotal bytes\b|\b(amount|volume) of data\b|\bdata volume\b"
                  r"|\b\d[\d,.]*\s*(bytes|kb|mb|gb)\b(?!\s*(per|/))",
    "avg_packet_size": r"\bpacket sizes?\b|\b(average|avg|mean) size\b",
    "duration_seconds": r"\bduration\b|\blasted\b|\bshort[- ]lived\b|\blong[- ]lived\b|\bover\s+\d[\d.]*\s*s(ec(ond)?s?)?\b",
    "packets_per_second": r"\bpackets?\s+(per|a|each)\s+second\b|\bpackets?/s\b|\bpps\b|\bpacket rate\b",
    "bytes_per_second": r"\bbytes?\s+(per|a|each)\s+second\b|\bbytes?/s\b|\b(kb|mb|gb)/s\b|\bthroughput\b"
                        r"|\bbit ?rate\b|\bbyte rate\b|\bdata rate\b|\btransfer rate\b|\bbandwidth\b",
    "tcp_syn_count": r"\bsyn\b(?![- ]?ack)",
    "tcp_fin_count": r"\bfin\b",
    "tcp_rst_count": r"\brst\b|\bresets?\b",
    "tcp_ack_count": r"(?<!syn-)(?<!syn )\back\b|\backnowledg",
    "tcp_psh_count": r"\bpsh\b|\bpush flags?\b",
    "src_port": r"\b(source|src|client|ephemeral) port\b",
    "dst_port": r"\b(destination|dst|target|server|service) port\b|(?<!source )(?<!src )\bport\s+\d+\b",
}

# Claims about information that is not in the prompt.
UNSUPPORTED_PATTERNS: dict[str, str] = {
    "payload": r"\bpayloads?\b|\bpacket contents?\b|\bmalicious (code|content|payload)\b|\bshellcode\b",
    "ttl": r"\bttl\b|\btime[- ]to[- ]live\b",
    "tcp_window": r"\bwindow size\b",
    "http_fields": r"\buser[- ]agent\b|\burls?\b|\buri\b|\bhttp (method|request|header)s?\b|\b(get|post) requests?\b",
    "dns_fields": r"\bdns quer(y|ies)\b|\bdomain names?\b|\bhostnames?\b",
    "tls_fields": r"\b(tls|ssl) (handshake|certificate)s?\b|\bcertificates?\b|\bja3\b",
    "reputation": r"\bgeolocat|\bcountry\b|\b(black|block|deny)list|\breputation\b|\bknown[- ]malicious\b|\bthreat intel",
    "timing": r"\bjitter\b|\brtt\b|\bround[- ]trip\b|\blatency\b|\binter[- ]arrival\b",
    "retransmission": r"\bretransmi",
    "fragmentation": r"\bfragment",
    "other_flows": r"\b(many|multiple|several|other|numerous) (hosts|destinations|ports|flows|connections)\b"
                   r"|\bprevious (flows|connections)\b|\bacross (hosts|ports)\b",
}

_FEATURE_RE = {k: re.compile(v, re.IGNORECASE) for k, v in FEATURE_PATTERNS.items()}
_UNSUPPORTED_RE = {k: re.compile(v, re.IGNORECASE) for k, v in UNSUPPORTED_PATTERNS.items()}


def mentioned_features(text: str, available: list[str] = APP_FEATURES) -> set[str]:
    return {f for f in available if _FEATURE_RE[f].search(text)}


def unsupported_claims(text: str) -> set[str]:
    return {k for k, rx in _UNSUPPORTED_RE.items() if rx.search(text)}


# ── Reference attributions ────────────────────────────────────────────────────

def attributions(ens: AppEnsemble, X: np.ndarray, X_background: np.ndarray,
                 kernel_nsamples: int = 500, seed: int = 0) -> dict[str, np.ndarray]:
    """Per-flow, per-feature attribution magnitudes for each reference method."""
    out = {"ae_error": ens.autoencoder.per_feature_error(X)}

    Z = ens.iforest.scaler.transform(X)
    tree = shap.TreeExplainer(ens.iforest.model._model)
    out["if_shap"] = np.abs(tree.shap_values(Z))

    rng = np.random.default_rng(seed)
    bg = X_background[rng.choice(len(X_background), size=min(50, len(X_background)), replace=False)]
    kernel = shap.KernelExplainer(ens.score, bg)
    out["ensemble_shap"] = np.abs(kernel.shap_values(X, nsamples=kernel_nsamples, silent=True))
    return out


def top_k(attr_row: np.ndarray, features: list[str], k: int) -> list[str]:
    return [features[i] for i in np.argsort(-attr_row)[:k]]


def agreement(mentioned: set[str], reference: list[str]) -> dict:
    hit = mentioned & set(reference)
    return {
        "precision": len(hit) / len(mentioned) if mentioned else np.nan,
        "recall": len(hit) / len(reference),
        "any_hit": float(bool(hit)),
        "jaccard": len(hit) / len(mentioned | set(reference)),
    }

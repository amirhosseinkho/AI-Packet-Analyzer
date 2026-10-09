"""Tiny synthetic split used only by the smoke tests and ``--synthetic`` dry runs.

Its numbers mean nothing; it exists so the pipeline can be checked without
downloading several gigabytes of data.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from . import APP_FEATURES
from .data import BENIGN, Split, _derive_rates


def _flows(n: int, rng: np.random.Generator, attack: str, start: pd.Timestamp) -> pd.DataFrame:
    df = pd.DataFrame({
        "packet_count": rng.poisson(20, n) + 1,
        "duration_seconds": rng.exponential(2.0, n),
        "tcp_syn_count": rng.integers(0, 2, n),
        "tcp_fin_count": rng.integers(0, 2, n),
        "tcp_rst_count": np.zeros(n, dtype=int),
        "tcp_ack_count": rng.poisson(15, n),
        "tcp_psh_count": rng.poisson(3, n),
        "src_port": rng.integers(1024, 65535, n),
        "dst_port": rng.choice([80, 443, 53, 22], n),
    })
    df["byte_count"] = df["packet_count"] * rng.normal(600, 100, n).clip(60)
    if attack == "PortScan":
        df["tcp_syn_count"] = rng.integers(20, 60, n)
        df["tcp_ack_count"] = rng.integers(0, 3, n)
        df["dst_port"] = rng.integers(1, 1024, n)
        df["packet_count"] = df["tcp_syn_count"] + 1
        df["byte_count"] = df["packet_count"] * 60
    elif attack == "DoS":
        df["packet_count"] = rng.poisson(800, n)
        df["byte_count"] = df["packet_count"] * 70
        df["duration_seconds"] = rng.exponential(0.5, n)
    df = _derive_rates(df)
    df["src_ip"] = "10.0.0." + pd.Series(rng.integers(1, 250, n)).astype(str)
    df["dst_ip"] = "192.168.1." + pd.Series(rng.integers(1, 250, n)).astype(str)
    df["protocol"] = "TCP"
    df["timestamp"] = start + pd.to_timedelta(np.sort(rng.uniform(0, 3600, n)), unit="s")
    df["attack"] = attack
    df["y"] = int(attack != BENIGN)
    return df


def synthetic_split(seed: int = 0, n: int = 600) -> Split:
    rng = np.random.default_rng(seed)
    t0 = pd.Timestamp("2026-01-05 09:00")
    train = _flows(n, rng, BENIGN, t0)
    val = _flows(n // 3, rng, BENIGN, t0 + pd.Timedelta(hours=1))
    t2 = t0 + pd.Timedelta(hours=2)
    test = pd.concat([_flows(n // 2, rng, BENIGN, t2), _flows(n // 10, rng, "PortScan", t2),
                      _flows(n // 10, rng, "DoS", t2)], ignore_index=True)
    return Split("synthetic", list(APP_FEATURES), train, val, test)

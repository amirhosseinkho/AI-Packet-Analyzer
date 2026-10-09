"""Dataset loaders and leakage-free temporal splits.

Both datasets are mapped onto the 13 flow features the application computes
(``FlowStatistics.to_feature_vector``), so the detectors see the same inputs
they see in production. Differences in how each dataset defines a feature are
listed in research/README.md under "Threats to validity".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from . import APP_FEATURES, DATA_DIR

BENIGN = "BENIGN"
CIC_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
_PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}

UNSW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts",
    "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
    "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "Label",
]

META_COLUMNS = ["src_ip", "dst_ip", "protocol", "timestamp", "attack", "y"]


@dataclass
class Split:
    """Feature matrices plus labels for one train/validation/test split."""

    name: str
    features: list[str]
    train: pd.DataFrame  # benign only
    val: pd.DataFrame    # benign only, later in time than train
    test: pd.DataFrame   # benign and attacks, later in time than val

    def X(self, part: str) -> np.ndarray:
        return getattr(self, part)[self.features].to_numpy(dtype=np.float32)

    def describe(self) -> dict:
        return {
            "dataset": self.name,
            "features": self.features,
            "n_train": len(self.train),
            "n_val": len(self.val),
            "n_test": len(self.test),
            "test_attack_counts": self.test["attack"].value_counts().to_dict(),
            "train_time_range": _time_range(self.train),
            "val_time_range": _time_range(self.val),
            "test_time_range": _time_range(self.test),
        }


def _time_range(df: pd.DataFrame) -> list[str]:
    if df.empty:
        return []
    return [str(df["timestamp"].min()), str(df["timestamp"].max())]


def _derive_rates(df: pd.DataFrame) -> pd.DataFrame:
    """Recompute derived features exactly as FlowStatistics.finalise() does."""
    pkts = df["packet_count"].astype(float)
    byts = df["byte_count"].astype(float)
    dur = df["duration_seconds"].astype(float)
    df["avg_packet_size"] = np.where(pkts > 0, byts / pkts.where(pkts > 0, 1), 0.0)
    df["packets_per_second"] = np.where(dur > 0, pkts / dur.where(dur > 0, 1), 0.0)
    df["bytes_per_second"] = np.where(dur > 0, byts / dur.where(dur > 0, 1), 0.0)
    return df


def _clean_label(label: str) -> str:
    label = re.sub(r"[^\x20-\x7e]", "-", str(label)).strip()
    label = re.sub(r"\s*-+\s*", " - ", label)
    return re.sub(r"\s+", " ", label)


# ── CIC-IDS2017 ────────────────────────────────────────────────────────────────

def load_cic_ids2017(root: Path | None = None) -> pd.DataFrame:
    """Load the CICFlowMeter CSVs that include timestamps (GeneratedLabelledFlows)."""
    root = root or DATA_DIR / "cic-ids2017"
    by_name = {p.name: p for p in sorted(root.rglob("*.csv")) if p.name.split("-")[0] in CIC_DAYS}
    files = sorted(by_name.values(), key=lambda p: p.name)
    if not files:
        raise FileNotFoundError(
            f"No CIC-IDS2017 CSVs under {root}. Download it by hand, then run: python scripts/prepare_data.py"
        )
    frames = []
    for path in files:
        raw = pd.read_csv(path, encoding="latin-1", low_memory=False, skipinitialspace=True)
        raw.columns = [c.strip() for c in raw.columns]
        if "Timestamp" not in raw.columns:
            raise ValueError(
                f"{path.name} has no Timestamp column. Use GeneratedLabelledFlows "
                "(TrafficLabelling), not MachineLearningCVE: the temporal split needs time."
            )
        raw = raw.dropna(subset=["Label"])
        df = pd.DataFrame({
            "packet_count": raw["Total Fwd Packets"] + raw["Total Backward Packets"],
            "byte_count": raw["Total Length of Fwd Packets"] + raw["Total Length of Bwd Packets"],
            "duration_seconds": raw["Flow Duration"].clip(lower=0) / 1e6,
            "tcp_syn_count": raw["SYN Flag Count"],
            "tcp_fin_count": raw["FIN Flag Count"],
            "tcp_rst_count": raw["RST Flag Count"],
            "tcp_ack_count": raw["ACK Flag Count"],
            "tcp_psh_count": raw["PSH Flag Count"],
            "src_port": raw["Source Port"],
            "dst_port": raw["Destination Port"],
        })
        df = _derive_rates(df)
        df["src_ip"] = raw["Source IP"].astype(str)
        df["dst_ip"] = raw["Destination IP"].astype(str)
        df["protocol"] = raw["Protocol"].map(_PROTO_NAMES).fillna("OTHER")
        df["timestamp"] = _parse_cic_timestamps(raw["Timestamp"])
        df["day"] = path.name.split("-")[0]
        df["attack"] = raw["Label"].map(_clean_label)
        df["y"] = (df["attack"] != BENIGN).astype(int)
        frames.append(df)
    data = pd.concat(frames, ignore_index=True)
    data[APP_FEATURES] = data[APP_FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return data


def _parse_cic_timestamps(ts: pd.Series) -> pd.Series:
    """CIC-IDS2017 writes some afternoon times on a 12-hour clock without AM/PM.

    Capture ran roughly 08:00-17:00, so hours below 8 are shifted by 12 hours.
    """
    parsed = pd.to_datetime(ts.astype(str).str.strip(), dayfirst=True, format="mixed", errors="coerce")
    afternoon = parsed.dt.hour < 8
    return parsed.where(~afternoon, parsed + pd.Timedelta(hours=12))


def split_cic_ids2017(data: pd.DataFrame, val_fraction: float = 0.2) -> Split:
    """Train/validate on Monday (benign only); test on Tuesday-Friday."""
    monday = data[(data["day"] == "Monday") & (data["y"] == 0)].sort_values("timestamp")
    cut = int(len(monday) * (1 - val_fraction))
    test = data[data["day"] != "Monday"]
    return Split("CIC-IDS2017", list(APP_FEATURES), monday.iloc[:cut], monday.iloc[cut:], test)


# ── UNSW-NB15 ──────────────────────────────────────────────────────────────────

def _to_port(s: pd.Series) -> pd.Series:
    s = s.astype(str).str.strip()
    hex_mask = s.str.startswith("0x")
    out = pd.to_numeric(s.where(~hex_mask), errors="coerce")
    out[hex_mask] = s[hex_mask].apply(lambda v: int(v, 16))
    return out.fillna(0)


def load_unsw_nb15(root: Path | None = None) -> pd.DataFrame:
    """Load the four raw UNSW-NB15 CSVs (UNSW-NB15_1.csv ... UNSW-NB15_4.csv)."""
    root = root or DATA_DIR / "unsw-nb15"
    files = sorted({p.name: p for p in root.rglob("UNSW-NB15_[1-4].csv")}.values(), key=lambda p: p.name)
    if not files:
        raise FileNotFoundError(
            f"No UNSW-NB15 CSVs under {root}. Download it by hand, then run: python scripts/prepare_data.py"
        )
    raw = pd.concat(
        (pd.read_csv(p, header=None, names=UNSW_COLUMNS, encoding="latin-1", low_memory=False) for p in files),
        ignore_index=True,
    )
    df = pd.DataFrame({
        "packet_count": raw["Spkts"] + raw["Dpkts"],
        "byte_count": raw["sbytes"] + raw["dbytes"],
        "duration_seconds": raw["dur"].clip(lower=0),
        "src_port": _to_port(raw["sport"]),
        "dst_port": _to_port(raw["dsport"]),
    })
    df = _derive_rates(df)
    for flag in ("tcp_syn_count", "tcp_fin_count", "tcp_rst_count", "tcp_ack_count", "tcp_psh_count"):
        df[flag] = np.nan  # not recorded per flow in UNSW-NB15
    df["src_ip"] = raw["srcip"].astype(str)
    df["dst_ip"] = raw["dstip"].astype(str)
    df["protocol"] = raw["proto"].astype(str).str.upper()
    df["timestamp"] = pd.to_datetime(raw["Stime"], unit="s")
    cat = raw["attack_cat"].fillna("").astype(str).str.strip().replace({"Backdoors": "Backdoor"})
    df["y"] = raw["Label"].astype(int)
    df["attack"] = np.where(df["y"] == 0, BENIGN, cat.where(cat != "", "Unknown"))
    return df


def split_unsw_nb15(data: pd.DataFrame, features: list[str], cut_quantile: float = 0.4,
                    val_fraction: float = 0.2) -> Split:
    """Benign flows before a time cut train and validate; everything after it is test."""
    data = data.sort_values("timestamp")
    cut_time = data["timestamp"].quantile(cut_quantile)
    early_benign = data[(data["timestamp"] < cut_time) & (data["y"] == 0)]
    cut = int(len(early_benign) * (1 - val_fraction))
    test = data[data["timestamp"] >= cut_time]
    return Split("UNSW-NB15", features, early_benign.iloc[:cut], early_benign.iloc[cut:], test)


# ── Subsampling ───────────────────────────────────────────────────────────────

def subsample(split: Split, n_train: int, n_val: int, test_benign_cap: int,
              test_attack_cap: int, train_seed: int, test_seed: int = 0) -> Split:
    """Random caps keep OCSVM/LOF tractable; the test sample is fixed across seeds.

    Attack classes are capped separately from benign traffic, so PR-AUC is
    reported at a stated, not accidental, attack prevalence.
    """
    def cap(df: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
        return df.sample(n=n, random_state=seed) if len(df) > n else df

    parts = [
        cap(group, test_benign_cap if attack == BENIGN else test_attack_cap, test_seed)
        for attack, group in split.test.groupby("attack")
    ]
    test = pd.concat(parts).sort_values("timestamp")
    return Split(split.name, split.features,
                 cap(split.train, n_train, train_seed),
                 cap(split.val, n_val, train_seed),
                 test)

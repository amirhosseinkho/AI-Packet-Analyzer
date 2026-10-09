"""Fast checks that run without the datasets or an LLM (python -m pytest tests)."""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pa_research import APP_FEATURES  # noqa: E402
from pa_research.data import BENIGN, _parse_cic_timestamps, subsample  # noqa: E402
from pa_research.explain import agreement, mentioned_features, unsupported_claims  # noqa: E402
from pa_research.metrics import detection_metrics, threshold_at_fpr  # noqa: E402
from pa_research.models import ALL_MODELS, AppEnsemble, build  # noqa: E402
from pa_research.synthetic import synthetic_split  # noqa: E402


def test_feature_mentions():
    text = ("This TCP flow sent 45 SYN packets with almost no ACK responses to destination "
            "port 22 within a short-lived connection, at 900 packets per second.")
    assert mentioned_features(text) == {
        "tcp_syn_count", "tcp_ack_count", "dst_port", "duration_seconds", "packets_per_second",
    }


def test_rates_are_not_counts():
    assert mentioned_features("It sent 120 packets per second.") == {"packets_per_second"}
    assert mentioned_features("It sent 120 packets in total.") == {"packet_count"}
    assert mentioned_features("A SYN-ACK was returned.") == set()


def test_unsupported_claims():
    assert unsupported_claims("The payload contains shellcode and the TTL is low.") == {"payload", "ttl"}
    assert unsupported_claims("The host is probing many ports.") == {"other_flows"}
    assert unsupported_claims("High SYN count suggests a scan.") == set()


def test_agreement():
    a = agreement({"tcp_syn_count", "dst_port"}, ["tcp_syn_count", "packet_count", "byte_count"])
    assert a["precision"] == 0.5 and abs(a["recall"] - 1 / 3) < 1e-9 and a["any_hit"] == 1.0
    assert np.isnan(agreement(set(), ["packet_count"])["precision"])


def test_threshold_uses_validation_quantile():
    val = np.arange(1000, dtype=float)
    assert threshold_at_fpr(val, 0.01) == np.quantile(val, 0.99)


def test_afternoon_timestamps_shift():
    ts = _parse_cic_timestamps(pd.Series(["7/7/2017 3:30", "7/7/2017 9:15"]))
    assert list(ts.dt.hour) == [15, 9]


def test_split_is_temporal_and_benign_only():
    split = synthetic_split()
    assert (split.train["attack"] == BENIGN).all() and (split.val["attack"] == BENIGN).all()
    assert split.train["timestamp"].max() < split.val["timestamp"].min() < split.test["timestamp"].min()
    sub = subsample(split, 100, 50, 100, 10, train_seed=1)
    assert len(sub.train) == 100 and (sub.test["attack"] != BENIGN).sum() == 20


def test_all_detectors_run():
    split = synthetic_split(n=300)
    for name in ALL_MODELS:
        det = build(name, seed=0, ae_epochs=2).fit(split.X("train"))
        if isinstance(det, AppEnsemble):
            det.ae_max = float(det.autoencoder.score(split.X("val")).max())
        scores = det.score(split.X("test"))
        thr = threshold_at_fpr(det.score(split.X("val")), 0.01)
        overall, per_attack = detection_metrics(scores, split.test, thr)
        assert scores.shape == (len(split.test),)
        assert 0 <= overall["roc_auc"] <= 1 and {r["attack"] for r in per_attack} == {"PortScan", "DoS"}


def test_feature_order_matches_app():
    from app.flow.statistics import FlowStatistics
    flow = FlowStatistics(flow_id="x", src_ip="0", dst_ip="0", protocol="TCP")
    assert flow.feature_names == APP_FEATURES

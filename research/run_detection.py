"""RQ1: how well does unsupervised flow anomaly detection work, and how fast?

Examples:
    python run_detection.py --setting cic            # CIC-IDS2017, in-domain
    python run_detection.py --setting unsw           # UNSW-NB15, in-domain
    python run_detection.py --setting cic-to-unsw    # train on CIC Monday, test on UNSW
    python run_detection.py --synthetic --seeds 0    # pipeline check, numbers are meaningless
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import torch

from pa_research import COMMON_FEATURES, RESULTS_DIR
from pa_research import data as D
from pa_research.metrics import binary_metrics, detection_metrics, threshold_at_fpr
from pa_research.models import ALL_MODELS, AppEnsemble, build
from pa_research.synthetic import synthetic_split


def load_split(setting: str) -> D.Split:
    if setting == "cic":
        return D.split_cic_ids2017(D.load_cic_ids2017())
    if setting == "unsw":
        return D.split_unsw_nb15(D.load_unsw_nb15(), COMMON_FEATURES)
    if setting == "cic-to-unsw":
        cic = D.split_cic_ids2017(D.load_cic_ids2017())
        unsw = D.split_unsw_nb15(D.load_unsw_nb15(), COMMON_FEATURES)
        return D.Split("CIC-IDS2017 -> UNSW-NB15", COMMON_FEATURES, cic.train, cic.val, unsw.test)
    raise ValueError(setting)


def git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--setting", choices=["cic", "unsw", "cic-to-unsw"], default="cic")
    ap.add_argument("--synthetic", action="store_true", help="use the tiny synthetic split")
    ap.add_argument("--models", nargs="+", default=ALL_MODELS, choices=ALL_MODELS)
    ap.add_argument("--seeds", nargs="+", type=int, default=[0, 1, 2, 3, 4])
    ap.add_argument("--fpr", type=float, default=0.01)
    ap.add_argument("--n-train", type=int, default=20_000)
    ap.add_argument("--n-val", type=int, default=20_000)
    ap.add_argument("--test-benign-cap", type=int, default=100_000)
    ap.add_argument("--test-attack-cap", type=int, default=5_000)
    ap.add_argument("--ae-epochs", type=int, default=50)
    ap.add_argument("--out", default=None, help="output folder name under results/")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    started = datetime.now(timezone.utc)
    full = synthetic_split() if args.synthetic else load_split(args.setting)
    name = "synthetic" if args.synthetic else args.setting
    out = RESULTS_DIR / (args.out or f"{started:%Y%m%d}_{name}")
    out.mkdir(parents=True, exist_ok=True)

    rows, attack_rows, split_info = [], [], None
    for seed in args.seeds:
        split = D.subsample(full, args.n_train, args.n_val, args.test_benign_cap,
                            args.test_attack_cap, train_seed=seed)
        split_info = split.describe()
        X_tr, X_val, X_te = split.X("train"), split.X("val"), split.X("test")
        trained = {}
        for model_name in args.models:
            t0 = time.perf_counter()
            if model_name == "ensemble" and {"isolation_forest", "autoencoder"} <= trained.keys():
                det = AppEnsemble.from_parts(trained["isolation_forest"], trained["autoencoder"])
            else:
                det = build(model_name, seed, args.ae_epochs).fit(X_tr)
            fit_s = time.perf_counter() - t0
            trained[model_name] = det

            if isinstance(det, AppEnsemble):
                # Fix the AE normaliser on validation data so the threshold and the
                # test scores are on the same scale (the app uses each batch's max).
                det.ae_max = float(np.max(det.autoencoder.score(X_val))) or 1.0
            thr = threshold_at_fpr(det.score(X_val), args.fpr)
            t0 = time.perf_counter()
            scores = det.score(X_te)
            score_s = time.perf_counter() - t0

            overall, per_attack = detection_metrics(scores, split.test, thr)
            row = {"model": model_name, "seed": seed, **overall,
                   "fit_seconds": fit_s, "flows_per_second": len(X_te) / score_s}
            if isinstance(det, AppEnsemble):
                deployed = binary_metrics(det.deployed_decision(X_te), split.test)
                row.update({"deployed_rule_recall": deployed["recall"], "deployed_rule_fpr": deployed["fpr"]})
            rows.append(row)
            attack_rows += [{"model": model_name, "seed": seed, **r} for r in per_attack]
            print(f"seed={seed} {model_name:16s} ROC-AUC={overall['roc_auc']:.3f} "
                  f"PR-AUC={overall['pr_auc']:.3f} recall@{args.fpr:.0%}FPR={overall['recall_at_fpr']:.3f} "
                  f"({row['flows_per_second']:.0f} flows/s)")

    per_seed = pd.DataFrame(rows)
    per_attack = pd.DataFrame(attack_rows)
    per_seed.to_csv(out / "per_seed.csv", index=False)
    per_attack.to_csv(out / "per_attack.csv", index=False)

    metrics = ["roc_auc", "pr_auc", "recall_at_fpr", "test_fpr", "flows_per_second"]
    summary = per_seed.groupby("model", sort=False)[metrics].agg(["mean", "std"])
    summary.to_csv(out / "summary.csv")
    attack_summary = (per_attack.groupby(["attack", "model"])[["roc_auc", "recall_at_fpr"]]
                      .mean().unstack("model"))
    attack_summary.to_csv(out / "per_attack_summary.csv")

    md = [f"# Detection results: {full.name}", "",
          f"Mean ± std over seeds {args.seeds}. Threshold set on benign validation flows at {args.fpr:.0%} FPR.", "",
          "| Model | ROC-AUC | PR-AUC | Recall @ FPR | Test FPR | Flows/s |",
          "|---|---|---|---|---|---|"]
    for model_name, r in summary.iterrows():
        cells = [f"{r[(m, 'mean')]:.3f} ± {r[(m, 'std')]:.3f}" if m != "flows_per_second"
                 else f"{r[(m, 'mean')]:,.0f}" for m in metrics]
        md.append(f"| {model_name} | " + " | ".join(cells) + " |")
    md += ["", "## Recall at the fixed FPR, by attack type (mean over seeds)", "",
           attack_summary["recall_at_fpr"].round(3).to_markdown()]
    (out / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    run = {
        "setting": name, "started_utc": started.isoformat(), "commit": git_commit(), "args": vars(args),
        "split": split_info, "python": platform.python_version(), "torch": torch.__version__,
        "machine": platform.platform(), "processor": platform.processor(),
        "cuda": torch.cuda.is_available(),
    }
    (out / "run.json").write_text(json.dumps(run, indent=2, default=str), encoding="utf-8")
    print(f"\nWrote {out}")
    print("\n".join(md[:6 + len(summary)]))


if __name__ == "__main__":
    main()

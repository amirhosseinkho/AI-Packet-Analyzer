"""RQ2: are the LLM explanations faithful to why the detector flagged a flow?

For flows the deployed ensemble flags, the script asks the LLM for an
explanation with the application's own prompt (condition ``deployed``) and with
the same prompt plus the detector's top-k feature attributions (condition
``grounded``). It then compares the features each explanation names with the
reference attributions in pa_research.explain and counts unsupported claims.

Examples:
    python run_faithfulness.py --provider ollama --model llama3.2
    python run_faithfulness.py --provider openai --model gpt-4o-mini
    python run_faithfulness.py --synthetic --provider mock      # pipeline check only
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from pa_research import RESULTS_DIR
from pa_research import data as D
from pa_research.explain import agreement, attributions, mentioned_features, top_k, unsupported_claims
from pa_research.models import AppEnsemble
from pa_research.synthetic import synthetic_split

from app.ai.anomaly_detector import _classify_anomaly, _score_to_severity
from app.flow.statistics import FlowStatistics
from app.llm.explanation_engine import _SYSTEM_PROMPT, _build_prompt

REFERENCES = ["ae_error", "if_shap", "ensemble_shap"]


def make_provider(name: str, model: str | None):
    if name == "mock":
        from app.llm.providers.mock_provider import MockProvider
        return MockProvider()
    if name == "ollama":
        from app.llm.providers.ollama_provider import OllamaProvider
        return OllamaProvider(model=model)
    if name == "openai":
        from app.llm.providers.openai_provider import OpenAIProvider
        return OpenAIProvider(model=model)
    raise ValueError(name)


def to_flow(i: int, row: pd.Series) -> FlowStatistics:
    flow = FlowStatistics(
        flow_id=f"test-{i}", src_ip=row["src_ip"], dst_ip=row["dst_ip"],
        src_port=int(row["src_port"]), dst_port=int(row["dst_port"]), protocol=row["protocol"],
        packet_count=int(row["packet_count"]), byte_count=int(row["byte_count"]),
        duration_seconds=float(row["duration_seconds"]),
        avg_packet_size=float(row["avg_packet_size"]),
        packets_per_second=float(row["packets_per_second"]),
        bytes_per_second=float(row["bytes_per_second"]),
    )
    for flag in ("syn", "fin", "rst", "ack", "psh"):
        value = row.get(f"tcp_{flag}_count", 0)
        setattr(flow, f"tcp_{flag}_count", 0 if pd.isna(value) else int(value))
    return flow


def grounded_suffix(features: list[str], row: pd.Series) -> str:
    listed = ", ".join(f"{f} = {row[f]:.4g}" for f in features)
    return f"\n\nFeatures that contributed most to the anomaly score, largest first: {listed}."


async def explain_all(provider, prompts: list[dict], temperature: float, cache_path) -> dict:
    cache = {}
    if cache_path.exists():
        for line in cache_path.read_text(encoding="utf-8").splitlines():
            item = json.loads(line)
            cache[item["key"]] = item["text"]
    with cache_path.open("a", encoding="utf-8") as fh:
        for p in prompts:
            if p["key"] in cache:
                continue
            text = await provider.complete(prompt=p["prompt"], system=_SYSTEM_PROMPT,
                                           temperature=temperature, max_tokens=256)
            cache[p["key"]] = text
            fh.write(json.dumps({"key": p["key"], "text": text}) + "\n")
            fh.flush()
    return cache


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--setting", choices=["cic"], default="cic")
    ap.add_argument("--synthetic", action="store_true")
    ap.add_argument("--provider", choices=["mock", "ollama", "openai"], default="ollama")
    ap.add_argument("--model", default=None, help="LLM name, e.g. llama3.2 or gpt-4o-mini")
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--conditions", nargs="+", default=["deployed", "grounded"], choices=["deployed", "grounded"])
    ap.add_argument("--per-attack", type=int, default=10, help="flagged flows sampled per attack type")
    ap.add_argument("--benign-fp", type=int, default=20, help="flagged benign flows (false positives)")
    ap.add_argument("--k", type=int, default=3)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--n-train", type=int, default=20_000)
    ap.add_argument("--ae-epochs", type=int, default=50)
    ap.add_argument("--kernel-nsamples", type=int, default=500)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")

    started = datetime.now(timezone.utc)
    full = synthetic_split() if args.synthetic else D.split_cic_ids2017(D.load_cic_ids2017())
    split = D.subsample(full, args.n_train, args.n_train, 100_000, 5_000, train_seed=args.seed)
    name = "synthetic" if args.synthetic else args.setting
    model_tag = f"{args.provider}-{args.model or 'default'}".replace("/", "_").replace(":", "_")
    out = RESULTS_DIR / (args.out or f"{started:%Y%m%d}_faithfulness_{name}_{model_tag}")
    out.mkdir(parents=True, exist_ok=True)

    feats = split.features
    ens = AppEnsemble(args.seed, args.ae_epochs).fit(split.X("train"))
    ens.ae_max = float(np.max(ens.autoencoder.score(split.X("val")))) or 1.0

    test = split.test.reset_index(drop=True)
    flagged = test[ens.deployed_decision(split.X("test"))]
    rng = np.random.default_rng(args.seed)
    picks = []
    for attack, group in flagged.groupby("attack"):
        n = args.benign_fp if attack == D.BENIGN else args.per_attack
        picks.append(group.loc[rng.choice(group.index, size=min(n, len(group)), replace=False)])
    sample = pd.concat(picks).sort_index()
    X = sample[feats].to_numpy(dtype=np.float32)
    print(f"Explaining {len(sample)} flagged flows: {sample['attack'].value_counts().to_dict()}")

    attr = attributions(ens, X, split.X("val"), args.kernel_nsamples, args.seed)
    if_s, ae_s = ens.components(X)

    prompts, rows = [], []
    for j, (i, row) in enumerate(sample.iterrows()):
        flow = to_flow(i, row)
        result = {
            "flow_id": flow.flow_id, "if_score": float(if_s[j]), "ae_score": float(ae_s[j]),
            "ensemble_score": float((if_s[j] + ae_s[j]) / 2), "is_anomaly": True,
            "anomaly_type": _classify_anomaly(flow),
            "severity": _score_to_severity(float((if_s[j] + ae_s[j]) / 2)),
        }
        refs = {r: top_k(attr[r][j], feats, args.k) for r in REFERENCES}
        base = _build_prompt(flow, result)
        for cond in args.conditions:
            prompt = base + (grounded_suffix(refs["ensemble_shap"], row) if cond == "grounded" else "")
            key = f"{i}|{cond}|{model_tag}|{args.temperature}"
            prompts.append({"key": key, "prompt": prompt})
            rows.append({"test_index": i, "attack": row["attack"], "condition": cond, "key": key,
                         "heuristic_type": result["anomaly_type"],
                         **{f"top_{r}": ";".join(refs[r]) for r in REFERENCES}})

    provider = make_provider(args.provider, args.model)
    texts = asyncio.run(explain_all(provider, prompts, args.temperature, out / "explanations.jsonl"))

    records = []
    for r in rows:
        text = texts[r["key"]]
        mentioned = mentioned_features(text, feats)
        unsupported = unsupported_claims(text)
        rec = {**r, "explanation": text, "mentioned": ";".join(sorted(mentioned)),
               "n_mentioned": len(mentioned), "unsupported": ";".join(sorted(unsupported)),
               "hallucinated": float(bool(unsupported))}
        for ref in REFERENCES:
            for metric, value in agreement(mentioned, r[f"top_{ref}"].split(";")).items():
                rec[f"{ref}_{metric}"] = value
        records.append(rec)
    per_expl = pd.DataFrame(records)
    per_expl.to_csv(out / "per_explanation.csv", index=False)

    lines = [f"# Explanation faithfulness: {split.name}", "",
             f"LLM: {args.provider} / {args.model or 'provider default'}, temperature {args.temperature}. "
             f"{len(sample)} flagged flows, k = {args.k}. Chance precision = k / {len(feats)} = {args.k / len(feats):.3f}.",
             ""]
    summary_rows = []
    for cond, g in per_expl.groupby("condition", sort=False):
        s = {"condition": cond, "n": len(g),
             "no_feature_named": float((g["n_mentioned"] == 0).mean()),
             "hallucination_rate": g["hallucinated"].mean()}
        for ref in REFERENCES:
            s[f"{ref}_precision"] = g[f"{ref}_precision"].mean()
            s[f"{ref}_recall@k"] = g[f"{ref}_recall"].mean()
        summary_rows.append(s)
    summary = pd.DataFrame(summary_rows)
    summary.to_csv(out / "summary.csv", index=False)
    lines += [summary.round(3).to_markdown(index=False), "", "## Unsupported-claim categories", ""]
    cats = per_expl.assign(cat=per_expl["unsupported"].str.split(";")).explode("cat")
    cats = cats[cats["cat"] != ""].groupby(["condition", "cat"]).size().unstack(fill_value=0)
    lines.append(cats.to_markdown() if not cats.empty else "None found.")
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out / "run.json").write_text(json.dumps({
        "started_utc": started.isoformat(), "args": vars(args), "split": split.describe(),
        "system_prompt": _SYSTEM_PROMPT}, indent=2, default=str), encoding="utf-8")
    print("\n".join(lines))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()

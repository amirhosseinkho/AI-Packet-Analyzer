# Research: detection quality and explanation faithfulness

This folder turns the analyzer into a measurable study. It imports the
application's own detectors (`backend/app/ai`) and its LLM prompt
(`backend/app/llm/explanation_engine.py`) and evaluates them as shipped. Nothing
under `backend/` or `frontend/` is changed.

## Research questions

**RQ1. Detection.** How well does unsupervised, flow-level anomaly detection
(the app's Isolation Forest + autoencoder ensemble) find attacks when it is
trained on benign traffic only, and how does it compare with standard one-class
baselines?

**RQ2. Faithfulness.** When the LLM explains a flagged flow, do the features it
names match the features that actually drove the detector's score? How often
does it rely on information it was never given?

RQ2 is what separates this project from a dashboard. The app's prompt passes
the flow statistics and the anomaly scores, but not *why* the score is high, so
the LLM has to guess. The study measures how good that guess is, and whether
passing the detector's top feature attributions to the LLM (the `grounded`
condition) makes the explanations more faithful.

## Data

| Dataset | Role | Split |
|---|---|---|
| CIC-IDS2017 (GeneratedLabelledFlows CSVs, with timestamps) | main | train and validate on Monday (benign only: first 80% / last 20% by time); test on Tuesday to Friday |
| UNSW-NB15 (the four raw CSVs) | generalisation | benign flows before the 40th time percentile train and validate; every flow after it is test |
| CIC-IDS2017 → UNSW-NB15 | cross-dataset transfer | train on CIC Monday, test on UNSW, using the features both datasets share |

Every split is temporal: all training and validation flows come before every
test flow, and no attack flow is ever used for training or threshold
selection. Both datasets are mapped onto the same 13 features the application
computes (`FlowStatistics.to_feature_vector`). UNSW-NB15 does not record
per-flow TCP flag counts, so experiments that involve it use the 8 shared
features.

`python scripts/prepare_data.py` downloads both datasets (about 490 MB) from
public Hugging Face mirrors, checks them, and writes SHA-256 fingerprints to
[`data/manifest.json`](data/manifest.json):

- **CIC-IDS2017**: [`bvsam/cic-ids-2017`](https://huggingface.co/datasets/bvsam/cic-ids-2017),
  folder `traffic_labels/`. These are the official TrafficLabelling CSVs
  converted to Parquet, with timestamps in UTC. The script verifies that the
  label counts match the published ones exactly (2,830,743 labelled flows).
- **UNSW-NB15**: [`rdpahalavan/UNSW-NB15`](https://huggingface.co/datasets/rdpahalavan/UNSW-NB15),
  `Network-Flows/UNSW_Flow.parquet`. This is the UNSW-NB15 flow table with the
  original 49 features, re-derived by the mirror's authors and linked to the
  packets: 2,059,415 flows, against 2,540,047 in the four official CSVs (many
  of which are duplicates).

The official files from the [CIC](https://www.unb.ca/cic/datasets/ids-2017.html)
and [UNSW](https://research.unsw.edu.au/projects/unsw-nb15-dataset) sites need
a registration form or a SharePoint download. If they are placed in
`data/cic-ids2017/` or `data/unsw-nb15/`, the loaders use them instead.

## Protocol

- **Models**: the app's Isolation Forest, the app's autoencoder, the app's
  ensemble (same score formula as `AnomalyDetectorService.analyse`), One-Class
  SVM (RBF, ν = 0.01), Local Outlier Factor (novelty mode, k = 20), and a
  max-|z-score| threshold. All use the app's `StandardScaler` preprocessing.
- **Seeds**: 5 (0 to 4). The seed changes the training subsample and the model
  initialisation; the test sample is fixed.
- **Sizes** (defaults, configurable): 20,000 training and 20,000 validation
  flows; the test set keeps up to 100,000 benign flows and up to 5,000 flows per
  attack type. The caps keep One-Class SVM and LOF tractable and make the attack
  prevalence explicit, since it changes PR-AUC.
- **Metrics**: ROC-AUC, PR-AUC, and recall at 1% false-positive rate, overall
  and per attack type. The 1% threshold is set on benign *validation* flows,
  so the realised test FPR is reported next to it. For the ensemble, the
  operating point of the app's fixed rule (IF says anomaly OR AE error > mean +
  3σ) is also reported. Throughput is scoring speed in flows per second
  (scaling plus model inference, on the test set), with the hardware recorded
  in `run.json`.
- **Faithfulness**: for flagged flows (10 per attack type plus 20 benign false
  positives), three reference attributions are computed:
  - `ae_error`: the autoencoder's per-feature squared reconstruction error
    (exact, because the AE score is their mean);
  - `if_shap`: TreeSHAP on the Isolation Forest;
  - `ensemble_shap`: KernelSHAP on the ensemble score.

  The features an explanation names are extracted with an explicit lexicon
  ([`pa_research/explain.py`](pa_research/explain.py)) and compared with each
  reference's top 3: precision, recall@3, and how often no feature is named.
  Chance precision is 3/13. An explanation is counted as a **hallucination**
  when it relies on information that is not in the prompt (payload, TTL, DNS
  names, HTTP fields, certificates, reputation, timing, other flows). In the
  `grounded` condition the prompt includes the `ensemble_shap` top 3, so
  agreement with that reference is expected to rise; agreement with `ae_error`
  and `if_shap` is the informative comparison.

## Reproduce

```bash
cd research
pip install -r requirements.txt
python scripts/prepare_data.py                     # downloads and verifies the data
python -m pytest tests                             # fast checks, no data needed

python run_detection.py --setting cic              # RQ1, main
python run_detection.py --setting unsw             # RQ1, generalisation
python run_detection.py --setting cic-to-unsw      # RQ1, transfer

python run_faithfulness.py --provider ollama --model llama3.2      # RQ2, local LLM
python run_faithfulness.py --provider openai --model gpt-4o-mini   # RQ2, needs OPENAI_API_KEY
python run_faithfulness.py --provider hf --model Qwen/Qwen2.5-1.5B-Instruct   # RQ2, local, no key
```

Each run writes a folder under `results/` with per-seed and per-attack CSVs, a
`summary.md` table, and a `run.json` holding the git commit, arguments, split
sizes and time ranges, and library versions. Explanations are cached in
`explanations.jsonl`, so re-scoring does not call the LLM again.
`--synthetic` runs either script on a tiny generated split to check the
pipeline; its numbers mean nothing.

## Results (RQ1, run 2026-10-09)

Mean ± std over 5 seeds; 20,000 training flows; threshold set on benign validation flows at 1% FPR. Full per-seed and per-attack tables are in [`results/`](results/). Throughput was measured on a shared laptop (i7-10750H) and is indicative only.

**CIC-IDS2017** (test: 100,000 benign + up to 5,000 flows per attack type, Tuesday–Friday)

| Model | ROC-AUC | PR-AUC | Recall @ FPR | Test FPR | Flows/s |
|---|---|---|---|---|---|
| isolation_forest | 0.760 ± 0.010 | 0.470 ± 0.011 | 0.012 ± 0.007 | 0.020 ± 0.001 | 41,370 |
| autoencoder | 0.769 ± 0.030 | 0.548 ± 0.036 | 0.198 ± 0.016 | 0.047 ± 0.006 | 1,166,141 |
| ensemble | 0.760 ± 0.010 | 0.473 ± 0.014 | 0.021 ± 0.013 | 0.021 ± 0.001 | 36,988 |
| ocsvm | 0.504 ± 0.011 | 0.399 ± 0.009 | 0.169 ± 0.013 | 0.038 ± 0.001 | 17,004 |
| lof | 0.809 ± 0.020 | 0.579 ± 0.024 | 0.128 ± 0.027 | 0.044 ± 0.003 | 12,699 |
| zscore_max | 0.730 ± 0.002 | 0.495 ± 0.003 | 0.071 ± 0.001 | 0.017 ± 0.001 | 5,075,388 |

**UNSW-NB15** (temporal split)

| Model | ROC-AUC | PR-AUC | Recall @ FPR | Test FPR | Flows/s |
|---|---|---|---|---|---|
| isolation_forest | 0.729 ± 0.007 | 0.488 ± 0.015 | 0.084 ± 0.027 | 0.019 ± 0.002 | 56,977 |
| autoencoder | 0.819 ± 0.033 | 0.660 ± 0.025 | 0.506 ± 0.048 | 0.035 ± 0.003 | 911,869 |
| ensemble | 0.740 ± 0.011 | 0.557 ± 0.043 | 0.274 ± 0.164 | 0.026 ± 0.006 | 53,545 |
| ocsvm | 0.801 ± 0.009 | 0.607 ± 0.014 | 0.319 ± 0.021 | 0.032 ± 0.003 | 22,543 |
| lof | 0.805 ± 0.047 | 0.622 ± 0.039 | 0.222 ± 0.022 | 0.018 ± 0.001 | 58,366 |
| zscore_max | 0.744 ± 0.001 | 0.562 ± 0.001 | 0.246 ± 0.008 | 0.029 ± 0.002 | 10,961,007 |

**Transfer: trained on CIC-IDS2017 Monday, tested on UNSW-NB15** (8 shared features)

| Model | ROC-AUC | PR-AUC | Recall @ FPR | Test FPR | Flows/s |
|---|---|---|---|---|---|
| isolation_forest | 0.463 ± 0.013 | 0.206 ± 0.007 | 0.065 ± 0.010 | 0.097 ± 0.016 | 64,771 |
| autoencoder | 0.444 ± 0.071 | 0.225 ± 0.063 | 0.225 ± 0.175 | 0.355 ± 0.136 | 4,200,496 |
| ensemble | 0.464 ± 0.012 | 0.210 ± 0.010 | 0.069 ± 0.009 | 0.099 ± 0.015 | 63,426 |
| ocsvm | 0.540 ± 0.081 | 0.276 ± 0.074 | 0.140 ± 0.020 | 0.180 ± 0.102 | 23,450 |
| lof | 0.539 ± 0.030 | 0.272 ± 0.032 | 0.288 ± 0.038 | 0.309 ± 0.066 | 29,562 |
| zscore_max | 0.508 ± 0.034 | 0.277 ± 0.045 | 0.060 ± 0.005 | 0.029 ± 0.018 | 10,749,643 |

Findings:

- **The app's ensemble adds nothing over the Isolation Forest alone.** Its score averages the IF score with the autoencoder error divided by the batch maximum, which makes the AE term tiny, so the ensemble ranks flows almost exactly like the IF (CIC ROC-AUC 0.760 for both). The autoencoder on its own is better on both datasets (CIC PR-AUC 0.548 vs 0.473; UNSW 0.660 vs 0.557).
- **The deployed binary rule** (IF anomaly OR AE error > mean + 3σ) catches 14.9% ± 1.0% of CIC attacks at a 7.3% ± 0.4% false-positive rate.
- **Thresholds drift over time.** A threshold set at 1% FPR on Monday traffic gives 2–5% FPR on later days.
- **Detection depends strongly on the attack type.** On CIC, volumetric attacks are found (DoS Hulk recall 0.66 and DDoS 0.54 for the AE; Heartbleed 1.0 for all models), while brute force, web attacks and slow DoS stay near zero recall at 1% FPR. Flow statistics alone do not separate them from normal traffic.
- **No model transfers across datasets.** Trained on CIC and tested on UNSW, every model is at or below chance (ROC-AUC 0.44–0.54), so a detector must be retrained on the network where it is deployed.

RQ2 (explanation faithfulness, local Qwen2.5-1.5B-Instruct on GPU) is running; its results will be added from `results/*faithfulness*`.

## Threats to validity

- **Feature definitions differ.** CICFlowMeter counts payload bytes, while the
  app counts whole packet lengths; UNSW-NB15 has no flag counts. Absolute
  scores are therefore not comparable across datasets, only the protocol is.
- **Flag features in CIC-IDS2017 are binary.** CICFlowMeter's `SYN/FIN/RST/ACK/PSH
  Flag Count` columns are 0 or 1 per flow in this release, not counts, so the
  app's flag-count features carry less information here than they would on
  live traffic.
- **The UNSW-NB15 copy is a re-derivation**, not the official CSVs (see Data).
  Its attack mix is less dominated by duplicated "Generic" flows, so numbers
  are not directly comparable with papers that use the official CSVs.
- **Label quality.** CIC-IDS2017 has documented labelling and flow-construction
  errors (Engelen et al., 2021). A corrected release exists and can be loaded
  with the same code if its CSV columns match.
- **The lexicon is a proxy.** It can miss paraphrases or match loosely. Before
  reporting RQ2, 50 explanations should be annotated by hand to measure the
  extractor's precision and recall, and that agreement reported with the
  results.
- **Ensemble normalisation.** The app divides autoencoder errors by the batch
  maximum, which makes a flow's score depend on the rest of its batch. The
  study fixes this divisor on validation data so thresholds stay valid; the
  deployed behaviour is kept for the fixed-rule operating point.
- **Throughput** measures model scoring only, not packet capture or flow
  aggregation.

## References

- I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani. *Toward Generating a New
  Intrusion Detection Dataset and Intrusion Traffic Characterization.* ICISSP 2018.
- N. Moustafa, J. Slay. *UNSW-NB15: A Comprehensive Data Set for Network
  Intrusion Detection Systems.* MilCIS 2015.
- G. Engelen, V. Rimmer, W. Joosen. *Troubleshooting an Intrusion Detection
  Dataset: the CICIDS2017 Case Study.* IEEE Security and Privacy Workshops
  (WTMC) 2021.
- S. M. Lundberg, S.-I. Lee. *A Unified Approach to Interpreting Model
  Predictions.* NeurIPS 2017.

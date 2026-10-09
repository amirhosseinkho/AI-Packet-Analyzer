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

Download instructions are at the top of [`scripts/prepare_data.py`](scripts/prepare_data.py).
The script unpacks the archives and writes SHA-256 fingerprints of every CSV to
`data/manifest.json`. The data itself is not committed.

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
python scripts/prepare_data.py                     # after downloading the data
python -m pytest tests                             # fast checks, no data needed

python run_detection.py --setting cic              # RQ1, main
python run_detection.py --setting unsw             # RQ1, generalisation
python run_detection.py --setting cic-to-unsw      # RQ1, transfer

python run_faithfulness.py --provider ollama --model llama3.2      # RQ2, local LLM
python run_faithfulness.py --provider openai --model gpt-4o-mini   # RQ2, needs OPENAI_API_KEY
```

Each run writes a folder under `results/` with per-seed and per-attack CSVs, a
`summary.md` table, and a `run.json` holding the git commit, arguments, split
sizes and time ranges, and library versions. Explanations are cached in
`explanations.jsonl`, so re-scoring does not call the LLM again.
`--synthetic` runs either script on a tiny generated split to check the
pipeline; its numbers mean nothing.

## Results

Not run yet. This section will be filled in from the committed `summary.md`
files, with their run dates. No number will appear here that does not come
from a file in `results/`.

## Threats to validity

- **Feature definitions differ.** CICFlowMeter counts payload bytes, while the
  app counts whole packet lengths; UNSW-NB15 has no flag counts. Absolute
  scores are therefore not comparable across datasets, only the protocol is.
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

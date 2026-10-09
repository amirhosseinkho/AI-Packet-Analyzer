# Explanation faithfulness: CIC-IDS2017

LLM: hf / Qwen/Qwen2.5-1.5B-Instruct, temperature 0.0. 134 flagged flows, k = 3. Chance precision = k / 13 = 0.231.

| condition   |   n |   no_feature_named |   hallucination_rate |   ae_error_precision |   ae_error_recall@k |   if_shap_precision |   if_shap_recall@k |   ensemble_shap_precision |   ensemble_shap_recall@k |
|:------------|----:|-------------------:|---------------------:|---------------------:|--------------------:|--------------------:|-------------------:|--------------------------:|-------------------------:|
| deployed    | 134 |                  0 |                0.015 |                0.213 |               0.505 |               0.337 |              0.769 |                     0.33  |                    0.756 |
| grounded    | 134 |                  0 |                0.03  |                0.195 |               0.306 |               0.426 |              0.627 |                     0.427 |                    0.627 |

## Unsupported-claim categories

| condition   |   fragmentation |   http_fields |   other_flows |   payload |   timing |
|:------------|----------------:|--------------:|--------------:|----------:|---------:|
| deployed    |               0 |             1 |             1 |         0 |        0 |
| grounded    |               1 |             0 |             0 |         2 |        1 |

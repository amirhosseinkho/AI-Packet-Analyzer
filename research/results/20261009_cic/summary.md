# Detection results: CIC-IDS2017

Mean ± std over seeds [0, 1, 2, 3, 4]. Threshold set on benign validation flows at 1% FPR.

| Model | ROC-AUC | PR-AUC | Recall @ FPR | Test FPR | Flows/s |
|---|---|---|---|---|---|
| isolation_forest | 0.760 ± 0.010 | 0.470 ± 0.011 | 0.012 ± 0.007 | 0.020 ± 0.001 | 41,370 |
| autoencoder | 0.769 ± 0.030 | 0.548 ± 0.036 | 0.198 ± 0.016 | 0.047 ± 0.006 | 1,166,141 |
| ensemble | 0.760 ± 0.010 | 0.473 ± 0.014 | 0.021 ± 0.013 | 0.021 ± 0.001 | 36,988 |
| ocsvm | 0.504 ± 0.011 | 0.399 ± 0.009 | 0.169 ± 0.013 | 0.038 ± 0.001 | 17,004 |
| lof | 0.809 ± 0.020 | 0.579 ± 0.024 | 0.128 ± 0.027 | 0.044 ± 0.003 | 12,699 |
| zscore_max | 0.730 ± 0.002 | 0.495 ± 0.003 | 0.071 ± 0.001 | 0.017 ± 0.001 | 5,075,388 |

## Recall at the fixed FPR, by attack type (mean over seeds)

| attack                   |   autoencoder |   ensemble |   isolation_forest |   lof |   ocsvm |   zscore_max |
|:-------------------------|--------------:|-----------:|-------------------:|------:|--------:|-------------:|
| Bot                      |         0.021 |      0.016 |              0.016 | 0.389 |   0.016 |        0.024 |
| DDoS                     |         0.54  |      0     |              0     | 0.129 |   0.599 |        0.44  |
| DoS GoldenEye            |         0.037 |      0     |              0     | 0.035 |   0.002 |        0     |
| DoS Hulk                 |         0.661 |      0.132 |              0.055 | 0.227 |   0.629 |        0.126 |
| DoS Slowhttptest         |         0.137 |      0.035 |              0.035 | 0.079 |   0.059 |        0.033 |
| DoS slowloris            |         0.018 |      0     |              0     | 0.028 |   0.042 |        0     |
| FTP-Patator              |         0.063 |      0.003 |              0.003 | 0.179 |   0.071 |        0.013 |
| Heartbleed               |         1     |      1     |              1     | 0.545 |   1     |        1     |
| Infiltration             |         0.633 |      0.65  |              0.65  | 0.367 |   0.478 |        0.183 |
| PortScan                 |         0.276 |      0.001 |              0     | 0.297 |   0.073 |        0.003 |
| SSH-Patator              |         0     |      0     |              0     | 0     |   0     |        0     |
| Web Attack Brute Force   |         0.019 |      0.001 |              0.001 | 0.002 |   0.028 |        0     |
| Web Attack Sql Injection |         0     |      0     |              0     | 0     |   0     |        0     |
| Web Attack XSS           |         0.005 |      0.024 |              0.024 | 0.001 |   0     |        0.001 |

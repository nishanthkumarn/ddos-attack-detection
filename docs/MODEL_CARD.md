# Model card

## Intended use
Defensive research and educational detection of DDoS-like network flow behavior using CICDDoS2019-derived flow features.

## Not intended for
Automatic blocking, attribution, incident-response decisions, or deployment as the sole detector on production infrastructure.

## Evaluation
The trainer creates train/validation/test partitions. It prefers grouped file-aware splitting to reduce duplicate-flow leakage and falls back to stratified row splitting only when the dataset does not contain enough distinct files.

The decision threshold is selected on validation data with a configurable minimum-recall target. Final ROC-AUC, average precision, Brier score, precision, recall, F1 and confusion matrix are reported on the untouched test partition.

## Caveats
- CICFlowMeter feature generation and live feature generation must match for meaningful deployment parity.
- Dataset-specific artifacts can inflate apparent performance.
- Probability is a model estimate, not proof of an attack.
- Concept drift, encrypted traffic, new attack families and benign flash crowds can degrade performance.

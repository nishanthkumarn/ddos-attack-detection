from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

from sklearn.metrics import average_precision_score, roc_auc_score

MAX_BATCH_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_BATCH_ROWS = 20_000
LABEL_NAMES = {"label", "class", "target"}
BENIGN_LABELS = {"BENIGN", "BENIGN TRAFFIC", "NORMAL", "0"}


def evaluate_labeled_csv(content: bytes, filename: str, detector: Any) -> dict[str, Any]:
    if len(content) > MAX_BATCH_UPLOAD_BYTES:
        raise ValueError("CSV exceeds the 25 MB upload limit.")

    try:
        text = content.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
    except UnicodeDecodeError as exc:
        raise ValueError("CSV must be encoded as UTF-8.") from exc

    if not reader.fieldnames:
        raise ValueError("CSV is empty or has no header row.")

    label_column = next(
        (name for name in reader.fieldnames if name.strip().lower() in LABEL_NAMES),
        None,
    )
    if label_column is None:
        raise ValueError("A labeled CSV is required; expected Label, Class, or Target.")

    available = {name.strip().lower() for name in reader.fieldnames}
    feature_names = detector.feature_names
    matched_features = sum(name.strip().lower() in available for name in feature_names)
    minimum_matches = min(5, len(feature_names))
    if matched_features < minimum_matches:
        raise ValueError(
            f"CSV has only {matched_features} model feature columns; "
            f"at least {minimum_matches} are required."
        )

    results = []
    probabilities = []
    actuals = []
    predictions = []
    families: dict[str, dict[str, int]] = {}

    for row_number, raw_row in enumerate(reader, start=2):
        if row_number > MAX_BATCH_ROWS + 1:
            raise ValueError(f"CSV exceeds the {MAX_BATCH_ROWS:,}-row limit.")
        if None in raw_row:
            raise ValueError(f"Malformed CSV row at line {row_number}.")

        row = {str(key).strip().lower(): value for key, value in raw_row.items() if key is not None}
        raw_label = str(row.get(label_column.strip().lower()) or "").strip()
        if not raw_label:
            raise ValueError(f"Missing label at CSV line {row_number}.")

        actual = 0 if raw_label.upper() in BENIGN_LABELS else 1
        model_input: dict[str, Any] = {
            str(key): value for key, value in raw_row.items() if key is not None
        }
        label, probability, confidence, severity, _, mode = detector.predict(model_input)
        predicted = 1 if label == "DDoS" else 0
        probabilities.append(float(probability))
        actuals.append(actual)
        predictions.append(predicted)

        if actual:
            family = raw_label
            counts = families.setdefault(family, {"rows": 0, "detected": 0})
            counts["rows"] += 1
            counts["detected"] += int(predicted == 1)

        results.append(
            {
                "row": row_number - 1,
                "src_ip": row.get("src ip") or row.get("source ip") or "",
                "dst_ip": row.get("dst ip") or row.get("destination ip") or "",
                "protocol": row.get("protocol") or "",
                "actual_label": raw_label,
                "actual_class": "DDoS" if actual else "BENIGN",
                "predicted_label": label,
                "probability": round(float(probability), 6),
                "confidence": round(float(confidence), 6),
                "severity": severity,
                "mode": mode,
                "correct": actual == predicted,
            }
        )

    if not results:
        raise ValueError("CSV contains no flow rows.")

    tp = sum(actual == 1 and predicted == 1 for actual, predicted in zip(actuals, predictions))
    tn = sum(actual == 0 and predicted == 0 for actual, predicted in zip(actuals, predictions))
    fp = sum(actual == 0 and predicted == 1 for actual, predicted in zip(actuals, predictions))
    fn = sum(actual == 1 and predicted == 0 for actual, predicted in zip(actuals, predictions))
    attack_count = tp + fn
    benign_count = tn + fp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / attack_count if attack_count else 0.0
    specificity = tn / benign_count if benign_count else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    has_both_classes = bool(attack_count and benign_count)

    return {
        "filename": Path(filename).name,
        "rows": len(results),
        "model_version": detector.version,
        "threshold": detector.threshold,
        "metrics": {
            "accuracy": (tp + tn) / len(results),
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "specificity": specificity,
            "false_positive_rate": fp / benign_count if benign_count else 0.0,
            "false_negative_rate": fn / attack_count if attack_count else 0.0,
            "roc_auc": float(roc_auc_score(actuals, probabilities)) if has_both_classes else None,
            "average_precision": float(average_precision_score(actuals, probabilities)) if has_both_classes else None,
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        },
        "attack_families": [
            {
                "label": family,
                "rows": counts["rows"],
                "recall": counts["detected"] / counts["rows"],
            }
            for family, counts in sorted(families.items())
        ],
        "results": results,
    }
"""Leakage-aware CICDDoS2019 trainer.

Memory-safe trainer for very large CICDDoS2019 CSVs. It samples rows
directly from CSV chunks without ever materializing an entire file in RAM,
keeps file identity as a grouping key, creates train/validation/test
partitions, fits a calibrated binary detector, selects an operating
threshold on validation data, and reports final metrics on an untouched
test split.
"""
from __future__ import annotations

import json
import os
import random
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import warnings
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold, train_test_split

warnings.filterwarnings(
    "ignore",
    message=r"Columns .* have mixed types.*",
    category=pd.errors.DtypeWarning,
)

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "models" / "ddos_detector.joblib"
REPORT = ROOT / "models" / "training_report.json"
SEED = int(os.getenv("MODEL_RANDOM_SEED", "42"))
CAP = int(os.getenv("MODEL_SAMPLE_ROWS", "500000"))
CHUNK = int(os.getenv("MODEL_CHUNK_ROWS", "25000"))


def label_col(cols):
    for c in cols:
        if str(c).strip().lower() in {"label", "class", "target"}:
            return c
    raise ValueError("No label column found. Expected Label/Class/Target.")


def is_attack(v) -> int:
    return 0 if str(v).strip().upper() in {
        "BENIGN", "BENIGN TRAFFIC", "NORMAL", "0"
    } else 1


def csvs():
    files = sorted(RAW.rglob("*.csv"))
    if not files:
        raise FileNotFoundError(
            f"No CSV files under {RAW}. Put CICDDoS2019 CSV files in data/raw/."
        )
    return files


def reservoir_update(buf_x, buf_y, seen, x, y, cap, rng):
    """Maintain an exact fixed-size reservoir using block sampling.

    The previous implementation could generate invalid reservoir indexes when
    processing a large chunk. This version samples from the existing reservoir
    plus the new chunk using a hypergeometric draw, so indexes are always
    valid and memory remains bounded by ``cap`` plus one CSV chunk.
    """
    n = len(x)
    if n == 0:
        return buf_x, buf_y, seen

    # First chunk: initialize with at most cap rows.
    if buf_x is None:
        take = min(cap, n)
        buf_x = np.asarray(x[:take], dtype=np.float32).copy()
        buf_y = np.asarray(y[:take], dtype=np.int8).copy()
        seen = take
        x = x[take:]
        y = y[take:]
        n = len(x)
        if n == 0:
            return buf_x, buf_y, seen

    old_count = min(seen, cap)
    new_count = n
    total = seen + new_count

    # If the combined data still fits, keep everything.
    if total <= cap:
        return (
            np.concatenate((buf_x, np.asarray(x, dtype=np.float32))),
            np.concatenate((buf_y, np.asarray(y, dtype=np.int8))),
            total,
        )

    # Choose exactly `cap` rows uniformly from:
    #   - old_count rows represented by the current reservoir
    #   - new_count rows in this chunk
    # The number selected from each side follows the hypergeometric
    # distribution, preserving uniform sampling without storing the file.
    new_keep = int(rng.hypergeometric(new_count, old_count, cap))
    old_keep = cap - new_keep

    if old_keep:
        old_idx = rng.choice(old_count, size=old_keep, replace=False)
        old_x = buf_x[old_idx]
        old_y = buf_y[old_idx]
    else:
        old_x = np.empty((0, buf_x.shape[1]), dtype=np.float32)
        old_y = np.empty(0, dtype=np.int8)

    if new_keep:
        new_idx = rng.choice(new_count, size=new_keep, replace=False)
        new_x = np.asarray(x[new_idx], dtype=np.float32)
        new_y = np.asarray(y[new_idx], dtype=np.int8)
    else:
        new_x = np.empty((0, buf_x.shape[1]), dtype=np.float32)
        new_y = np.empty(0, dtype=np.int8)

    combined_x = np.concatenate((old_x, new_x))
    combined_y = np.concatenate((old_y, new_y))

    # Shuffle so subsequent updates do not depend on which side was appended.
    order = rng.permutation(len(combined_y))
    return combined_x[order], combined_y[order], total


def sample_data(files, cap):
    per_file_cap = max(1000, cap // max(len(files), 1))
    rng = np.random.default_rng(SEED)

    feature_names = None
    all_rows = []
    all_labels = []
    all_groups = []
    total_seen = 0

    for path in files:
        local_x = None
        local_y = None
        local_seen = 0

        try:
            reader = pd.read_csv(
                path,
                chunksize=CHUNK,
                low_memory=True,
                on_bad_lines="skip",
            )

            for chunk_number, chunk in enumerate(reader, start=1):
                lc = label_col(chunk.columns)

                if feature_names is None:
                    feature_names = [
                        c for c in chunk.columns
                        if c != lc
                        and not str(c).lower().startswith("unnamed")
                        and pd.api.types.is_numeric_dtype(chunk[c])
                    ]
                    if not feature_names:
                        raise ValueError(
                            f"No numeric feature columns found in {path.name}."
                        )

                numeric = [c for c in feature_names if c in chunk.columns]
                x = (
                    chunk.reindex(columns=numeric)
                    .replace([np.inf, -np.inf], np.nan)
                    .to_numpy(dtype=np.float32, copy=False)
                )
                y = chunk[lc].map(is_attack).to_numpy(dtype=np.int8)

                local_x, local_y, local_seen = reservoir_update(
                    local_x,
                    local_y,
                    local_seen,
                    x,
                    y,
                    per_file_cap,
                    rng,
                )
                total_seen += len(chunk)

                if chunk_number % 20 == 0:
                    print(
                        f"  {path.name}: {total_seen:,} total rows seen",
                        flush=True,
                    )

        except pd.errors.EmptyDataError:
            print(f"skipping empty CSV: {path.name}", flush=True)
            continue
        except pd.errors.ParserError as exc:
            raise RuntimeError(
                f"Could not parse {path.name}. The CSV contains malformed data "
                f"that pandas could not recover from: {exc}"
            ) from exc

        if local_seen:
            used = min(local_seen, per_file_cap)
            all_rows.append(local_x[:used].copy())
            all_labels.append(local_y[:used].copy())
            all_groups.extend([path.name] * used)

        print(
            f"processed {path.name}: {local_seen:,} rows seen; "
            f"{min(local_seen, per_file_cap):,} sampled",
            flush=True,
        )

    if not all_rows:
        raise ValueError("No usable rows were found in the CSV files.")

    X = np.vstack(all_rows).astype(np.float32, copy=False)
    y = np.concatenate(all_labels).astype(np.int8, copy=False)
    groups = np.asarray(all_groups)

    if len(set(y.tolist())) < 2:
        raise ValueError("Both BENIGN and attack rows are required.")

    print(
        f"sampling complete: {total_seen:,} rows seen, "
        f"{len(y):,} rows retained, {X.shape[1]} numeric features",
        flush=True,
    )
    return X, y, feature_names, groups, total_seen


def split_data(X, y, groups):
    # Prefer grouped splitting to reduce duplicate-flow/file leakage.
    if len(set(groups)) >= 3:
        try:
            sgkf = StratifiedGroupKFold(
                n_splits=5, shuffle=True, random_state=SEED
            )
            folds = list(sgkf.split(X, y, groups))
            train_idx, test_idx = folds[0]
            remaining = train_idx

            val_rel, train_rel = next(
                StratifiedGroupKFold(
                    n_splits=4, shuffle=True, random_state=SEED + 1
                ).split(X[remaining], y[remaining], groups[remaining])
            )
            val_idx, train_idx2 = remaining[val_rel], remaining[train_rel]

            if {0, 1} <= set(y[test_idx]) and {0, 1} <= set(y[val_idx]):
                return train_idx2, val_idx, test_idx, "grouped-file-split"
        except ValueError:
            pass

    train_idx, temp_idx = train_test_split(
        np.arange(len(y)),
        test_size=0.30,
        random_state=SEED,
        stratify=y,
    )
    val_idx, test_idx = train_test_split(
        temp_idx,
        test_size=2 / 3,
        random_state=SEED,
        stratify=y[temp_idx],
    )
    return train_idx, val_idx, test_idx, "stratified-row-split-fallback"


def calibrate_threshold(y, p):
    precision, recall, thresholds = precision_recall_curve(y, p)
    target = float(os.getenv("MODEL_MIN_RECALL", "0.90"))
    candidates = []

    for i, threshold in enumerate(thresholds):
        f1 = (
            2 * precision[i] * recall[i]
            / (precision[i] + recall[i] + 1e-12)
        )
        candidates.append(
            (
                float(threshold),
                float(precision[i]),
                float(recall[i]),
                float(f1),
            )
        )

    valid = [x for x in candidates if x[2] >= target]
    pool = valid or candidates
    return max(pool, key=lambda x: x[3]) if pool else (0.5, 0.0, 0.0, 0.0)


def metrics(y, p, threshold):
    pred = (p >= threshold).astype(np.int8)
    report = classification_report(
        y,
        pred,
        target_names=["BENIGN", "DDoS"],
        output_dict=True,
        zero_division=0,
    )
    return {
        "roc_auc": float(roc_auc_score(y, p)),
        "average_precision": float(average_precision_score(y, p)),
        "brier_score": float(brier_score_loss(y, p)),
        "threshold": float(threshold),
        "precision_at_threshold": float(report["DDoS"]["precision"]),
        "recall_at_threshold": float(report["DDoS"]["recall"]),
        "f1_at_threshold": float(report["DDoS"]["f1-score"]),
        "confusion_matrix": confusion_matrix(y, pred).tolist(),
        "classification_report": report,
    }


def main():
    random.seed(SEED)
    np.random.seed(SEED)

    files = csvs()
    print(
        f"found {len(files)} CSV files; "
        f"sample cap={CAP:,}, chunk={CHUNK:,}",
        flush=True,
    )

    X, y, features, groups, seen = sample_data(files, CAP)
    train_idx, val_idx, test_idx, split_method = split_data(X, y, groups)

    imputer = SimpleImputer(strategy="median")
    X_train = np.clip(imputer.fit_transform(X[train_idx]), -1e15, 1e15)
    X_val = np.clip(imputer.transform(X[val_idx]), -1e15, 1e15)
    X_test = np.clip(imputer.transform(X[test_idx]), -1e15, 1e15)
    y_train, y_val, y_test = y[train_idx], y[val_idx], y[test_idx]

    base = HistGradientBoostingClassifier(
        max_iter=int(os.getenv("MODEL_MAX_ITER", "350")),
        learning_rate=float(os.getenv("MODEL_LEARNING_RATE", "0.06")),
        max_leaf_nodes=int(os.getenv("MODEL_MAX_LEAF_NODES", "63")),
        l2_regularization=float(os.getenv("MODEL_L2", "2.0")),
        random_state=SEED,
    )

    clf = CalibratedClassifierCV(base, method="sigmoid", cv=3)
    print(
        f"training calibrated model on {len(y_train):,} rows...",
        flush=True,
    )
    clf.fit(X_train, y_train)

    p_val = clf.predict_proba(X_val)[:, 1]
    threshold, _, _, _ = calibrate_threshold(y_val, p_val)
    val_metrics = metrics(y_val, p_val, threshold)

    p_test = clf.predict_proba(X_test)[:, 1]
    test_metrics = metrics(y_test, p_test, threshold)

    n = min(5000, len(X_test))
    pi = permutation_importance(
        clf,
        X_test[:n],
        y_test[:n],
        n_repeats=3,
        random_state=SEED,
        scoring="average_precision",
        n_jobs=-1,
    )
    importance = sorted(
        zip(features, pi.importances_mean),
        key=lambda z: abs(z[1]),
        reverse=True,
    )[:30]

    feature_stats = {}
    for i, name in enumerate(features):
        col = X_train[:, i]
        feature_stats[name] = {
            "mean": float(np.mean(col)),
            "std": float(np.std(col)),
            "median": float(np.median(col)),
            "p01": float(np.percentile(col, 1)),
            "p99": float(np.percentile(col, 99)),
        }

    artifact = {
        "model": clf,
        "imputer": imputer,
        "feature_names": features,
        "version": "cicddos2019-hgb-calibrated-v4-memory-safe",
        "classes": ["BENIGN", "DDoS"],
        "threshold": threshold,
        "importance": [(n, float(v)) for n, v in importance],
        "feature_stats": feature_stats,
        "metrics": {"validation": val_metrics, "test": test_metrics},
        "training": {
            "dataset": "CICDDoS2019",
            "files": [str(p.relative_to(ROOT)) for p in files],
            "rows_seen": seen,
            "sampled_rows": len(y),
            "split_method": split_method,
            "train_rows": len(train_idx),
            "validation_rows": len(val_idx),
            "test_rows": len(test_idx),
            "random_seed": SEED,
            "sample_cap": CAP,
            "chunk_rows": CHUNK,
        },
    }

    OUT.parent.mkdir(exist_ok=True)
    joblib.dump(artifact, OUT, compress=3)
    REPORT.write_text(
        json.dumps(
            {k: v for k, v in artifact.items() if k not in {"model", "imputer"}},
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    print(
        json.dumps(
            artifact["training"] | {"validation": val_metrics, "test": test_metrics},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

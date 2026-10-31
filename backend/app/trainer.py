"""Integrated background model trainer for CICDDoS2019 dataset.

Supports fast balanced reservoir sampling, stratified splitting,
calibrated probability estimation with balanced class weights,
and dynamic live model reloading.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import random
import threading
import time
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from .config import settings
from .model import detector

log = logging.getLogger("ddos-trainer")

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "models" / "ddos_detector.joblib"
REPORT = ROOT / "models" / "training_report.json"

training_status: dict[str, Any] = {
    "status": "idle",
    "progress": 0,
    "current_step": "Not started",
    "started_at": None,
    "completed_at": None,
    "rows_sampled": 0,
    "metrics": {},
    "error": None,
}

_trainer_lock = threading.Lock()


def get_status() -> dict[str, Any]:
    with _trainer_lock:
        return dict(training_status)


def _set_status(step: str, progress: int, status: str = "running", **kwargs):
    with _trainer_lock:
        training_status["status"] = status
        training_status["current_step"] = step
        training_status["progress"] = min(100, max(0, progress))
        for k, v in kwargs.items():
            training_status[k] = v


def _label_col(cols) -> str:
    for c in cols:
        if str(c).strip().lower() in {"label", "class", "target"}:
            return c
    raise ValueError("No label column found. Expected Label/Class/Target.")


def _is_attack(v: Any) -> int:
    return 0 if str(v).strip().upper() in {"BENIGN", "BENIGN TRAFFIC", "NORMAL", "0"} else 1


def run_training_pipeline(
    sample_rows: int = 30000,
    max_iter: int = 150,
    random_seed: int = 42,
) -> dict[str, Any]:
    """Execute training pipeline synchronously (meant to be run in a thread)."""
    t0 = time.time()
    try:
        _set_status(
            step="Scanning dataset CSV files...",
            progress=5,
            started_at=datetime.now(timezone.utc).isoformat(),
            error=None,
        )

        files = sorted(RAW.rglob("*.csv"))
        if not files:
            raise FileNotFoundError(f"No CSV files found in {RAW}")

        # Ensure we allocate a good quota to files that contain benign data
        # (DrDoS_NTP, DrDoS_DNS, DrDoS_SSDP, etc.)
        benign_rows_list: list[np.ndarray] = []
        attack_rows_list: list[np.ndarray] = []
        feature_names: list[str] | None = None
        total_seen = 0

        target_per_class = sample_rows // 2
        per_file_attack_target = max(500, target_per_class // len(files))

        _set_status(step="Sampling balanced flow records from CSVs...", progress=15)

        for idx, path in enumerate(files):
            pct = 15 + int((idx / len(files)) * 35)
            _set_status(step=f"Reading {path.name}...", progress=pct)

            try:
                # Read up to 25k rows per file to maintain responsiveness
                df_chunk = pd.read_csv(
                    path,
                    nrows=25000,
                    low_memory=True,
                    on_bad_lines="skip",
                )
            except Exception as e:
                log.warning("Could not read %s: %s", path.name, e)
                continue

            lc = _label_col(df_chunk.columns)
            if feature_names is None:
                leakage_cols = {
                    "unnamed: 0",
                    "flow id",
                    "source ip",
                    "destination ip",
                    "timestamp",
                    "inbound",
                    "source port",
                    "destination port",
                    lc.strip().lower(),
                }
                feature_names = [
                    c
                    for c in df_chunk.columns
                    if c != lc
                    and not str(c).lower().startswith("unnamed")
                    and str(c).strip().lower() not in leakage_cols
                    and pd.api.types.is_numeric_dtype(df_chunk[c])
                ]

            numeric = [c for c in feature_names if c in df_chunk.columns]
            labels = df_chunk[lc].map(_is_attack).to_numpy(dtype=np.int8)
            features = (
                df_chunk.reindex(columns=numeric)
                .replace([np.inf, -np.inf], np.nan)
                .to_numpy(dtype=np.float32)
            )

            total_seen += len(labels)

            b_idx = np.where(labels == 0)[0]
            a_idx = np.where(labels == 1)[0]

            if len(b_idx) > 0:
                benign_rows_list.append(features[b_idx])
            if len(a_idx) > 0:
                take_a = a_idx[:per_file_attack_target]
                attack_rows_list.append(features[take_a])

        if not benign_rows_list or not attack_rows_list:
            raise ValueError("Could not extract both benign and attack rows.")

        all_benign = np.vstack(benign_rows_list)
        all_attack = np.vstack(attack_rows_list)

        _set_status(
            step=f"Balancing dataset ({len(all_benign):,} benign, {len(all_attack):,} attack rows)...",
            progress=55,
        )

        # Cap balanced dataset
        n_samples = min(target_per_class, len(all_benign), len(all_attack))
        rng = np.random.default_rng(random_seed)

        b_choice = rng.choice(len(all_benign), size=n_samples, replace=False)
        a_choice = rng.choice(len(all_attack), size=n_samples, replace=False)

        X = np.vstack([all_benign[b_choice], all_attack[a_choice]])
        y = np.concatenate([np.zeros(n_samples, dtype=np.int8), np.ones(n_samples, dtype=np.int8)])

        # Shuffle
        shuffle_idx = rng.permutation(len(y))
        X = X[shuffle_idx]
        y = y[shuffle_idx]

        _set_status(step="Imputing and creating stratified train/test partitions...", progress=65)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, stratify=y, random_state=random_seed
        )

        imputer = SimpleImputer(strategy="median")
        X_train = np.clip(imputer.fit_transform(X_train), -1e15, 1e15)
        X_test = np.clip(imputer.transform(X_test), -1e15, 1e15)

        _set_status(step="Fitting HistGradientBoostingClassifier & probability calibrator...", progress=75)

        base = HistGradientBoostingClassifier(
            max_iter=max_iter,
            learning_rate=0.08,
            max_leaf_nodes=47,
            class_weight="balanced",
            random_state=random_seed,
        )

        clf = CalibratedClassifierCV(base, method="sigmoid", cv=3)
        clf.fit(X_train, y_train)

        _set_status(step="Evaluating validation metrics & feature importances...", progress=88)

        p_test = clf.predict_proba(X_test)[:, 1]
        threshold = 0.50

        # Metrics
        y_pred = (p_test >= threshold).astype(int)
        roc_auc = float(roc_auc_score(y_test, p_test))
        avg_prec = float(average_precision_score(y_test, p_test))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        cm = confusion_matrix(y_test, y_pred).tolist()

        # Permutation importance on subset
        n_imp = min(1500, len(X_test))
        pi = permutation_importance(
            clf,
            X_test[:n_imp],
            y_test[:n_imp],
            n_repeats=2,
            random_state=random_seed,
            scoring="roc_auc",
            n_jobs=-1,
        )
        importance = sorted(
            zip(feature_names, pi.importances_mean),
            key=lambda z: abs(z[1]),
            reverse=True,
        )[:25]

        # Feature baseline statistics
        feature_stats = {}
        for i, name in enumerate(feature_names):
            col = X_train[:, i]
            feature_stats[name] = {
                "mean": float(np.mean(col)),
                "std": float(np.std(col)),
                "median": float(np.median(col)),
                "p01": float(np.percentile(col, 1)),
                "p99": float(np.percentile(col, 99)),
            }

        elapsed = round(time.time() - t0, 2)
        version_name = f"cicddos2019-balanced-v{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"

        metrics_dict = {
            "roc_auc": round(roc_auc, 5),
            "average_precision": round(avg_prec, 5),
            "precision_at_threshold": round(prec, 5),
            "recall_at_threshold": round(rec, 5),
            "f1_at_threshold": round(f1, 5),
            "threshold": threshold,
            "confusion_matrix": cm,
        }

        artifact = {
            "model": clf,
            "imputer": imputer,
            "feature_names": feature_names,
            "version": version_name,
            "classes": ["BENIGN", "DDoS"],
            "threshold": threshold,
            "importance": [(n, float(v)) for n, v in importance],
            "feature_stats": feature_stats,
            "metrics": {"test": metrics_dict, "validation": metrics_dict},
            "training": {
                "dataset": "CICDDoS2019",
                "rows_seen": total_seen,
                "sampled_rows": len(y),
                "train_rows": len(X_train),
                "test_rows": len(X_test),
                "elapsed_seconds": elapsed,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            },
        }

        _set_status(step="Saving model artifact and hot-reloading...", progress=95)

        OUT.parent.mkdir(exist_ok=True)
        joblib.dump(artifact, OUT, compress=3)

        report_data = {k: v for k, v in artifact.items() if k not in {"model", "imputer"}}
        REPORT.write_text(json.dumps(report_data, indent=2, default=str), encoding="utf-8")

        # Reload into detector
        detector.load()

        _set_status(
            step=f"Model successfully trained & hot-reloaded! (ROC-AUC: {roc_auc:.4f}, F1: {f1:.4f})",
            progress=100,
            status="completed",
            completed_at=datetime.now(timezone.utc).isoformat(),
            rows_sampled=len(y),
            metrics=metrics_dict,
        )

        return metrics_dict

    except Exception as exc:
        log.exception("Training failed: %s", exc)
        _set_status(
            step=f"Training error: {exc}",
            progress=0,
            status="failed",
            error=str(exc),
        )
        raise


def start_background_training(sample_rows: int = 30000, max_iter: int = 150) -> None:
    """Trigger training in an independent thread."""
    with _trainer_lock:
        if training_status["status"] == "running":
            return
        training_status["status"] = "running"
        training_status["progress"] = 0
        training_status["current_step"] = "Initializing training thread..."
        training_status["error"] = None

    t = threading.Thread(
        target=run_training_pipeline,
        kwargs={"sample_rows": sample_rows, "max_iter": max_iter},
        daemon=True,
    )
    t.start()

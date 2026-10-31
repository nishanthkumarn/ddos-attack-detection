from __future__ import annotations
from collections import deque

class DriftMonitor:
    """Reference-distribution z-score monitor for unlabeled live flow telemetry."""
    def __init__(self, window: int = 250, z_threshold: float = 4.0):
        self.window = window
        self.z_threshold = z_threshold
        self.history: dict[str, deque[float]] = {}
        self.samples = 0
        self.anomalies = 0
        self.feature_anomalies: dict[str, int] = {}

    def update(self, features: dict[str, float], baseline: dict[str, dict[str, float]]) -> list[dict]:
        self.samples += 1
        signals = []
        for name, value in features.items():
            if name not in baseline:
                continue
            try:
                x = float(value)
            except (TypeError, ValueError):
                continue
            q = self.history.setdefault(name, deque(maxlen=self.window)); q.append(x)
            b = baseline[name]
            std = max(float(b.get("std", 0.0)), 1e-9)
            z = abs((x - float(b.get("mean", 0.0))) / std)
            if len(q) >= 30 and z >= self.z_threshold:
                signals.append({"feature": name, "z_score": round(z, 3), "value": x})
                self.feature_anomalies[name] = self.feature_anomalies.get(name, 0) + 1
        if signals:
            self.anomalies += 1
        return sorted(signals, key=lambda x: x["z_score"], reverse=True)[:8]

    def snapshot(self) -> dict:
        return {"samples": self.samples, "anomalous_samples": self.anomalies,
                "anomaly_rate": self.anomalies / self.samples if self.samples else 0.0,
                "window": self.window, "z_threshold": self.z_threshold,
                "top_drift_features": sorted(self.feature_anomalies.items(), key=lambda x: x[1], reverse=True)[:10]}

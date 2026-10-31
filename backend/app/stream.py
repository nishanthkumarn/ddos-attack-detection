from __future__ import annotations

import asyncio
import ipaddress
import math
import random
import time
import uuid
from collections import deque
from datetime import datetime, timezone

try:
    from river import metrics
except ImportError:
    metrics = None

from .config import settings
from .db import insert_event, upsert_alert
from .drift import DriftMonitor
from .metrics import EVENTS, ALERTS, INFERENCE, STREAM_EVENTS, WS_CLIENTS, DRIFT
from .model import detector
from .schemas import FlowEvent


clients: set = set()

rng = random.Random(settings.random_seed)

latency_ms = deque(maxlen=500)

accuracy = metrics.Accuracy() if metrics else None

stream_state = {
    "running": True,
    "interval_ms": settings.demo_interval_ms,
    "events": 0,
    "attack_burst": False,
    "source": "synthetic",
    "last_event_at": None,
}

drift = DriftMonitor(
    settings.drift_window,
    settings.drift_z_threshold,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stat(name: str, key: str, fallback: float) -> float:
    """
    Get a training-distribution statistic from the model artifact.
    """
    value = detector.feature_stats.get(name, {}).get(key)

    try:
        value = float(value)
    except (TypeError, ValueError):
        return fallback

    if not math.isfinite(value):
        return fallback

    return value


def _positive_stat(name: str, key: str, fallback: float) -> float:
    """
    Training statistics occasionally contain malformed/overflowed negative
    values in the current CICDDoS2019 artifact.

    Synthetic traffic must never reproduce those invalid negative values.
    """
    value = _stat(name, key, fallback)
    return value if value > 0 else fallback


def _sample_feature(
    name: str,
    *,
    attack: bool,
    scale: float = 1.0,
    minimum: float = 0.0,
) -> float:
    """
    Sample a feature around the distribution learned during training.

    This is a simulator only. It does not alter the trained model.
    """
    stats = detector.feature_stats.get(name, {})

    median = stats.get("median")
    std = stats.get("std")

    try:
        median = float(median)
        std = float(std)
    except (TypeError, ValueError):
        median = 0.0
        std = 0.0

    if not math.isfinite(median):
        median = 0.0

    if not math.isfinite(std) or std < 0:
        std = 0.0

    # For attack traffic, move away from the benign-ish center using
    # the observed training dispersion. This produces coherent variation
    # instead of identical repeated feature vectors.
    if attack:
        direction = rng.choice((1.0, 1.0, 1.0, -1.0))
        value = median + direction * max(std * scale, abs(median) * 0.15)
    else:
        value = median + rng.gauss(0.0, max(std * 0.15, abs(median) * 0.03))

    if not math.isfinite(value):
        value = median

    return max(minimum, float(value))


def _safe(value: float, minimum: float = 0.0) -> float:
    if not math.isfinite(value):
        return minimum
    return max(minimum, float(value))


# ---------------------------------------------------------------------------
# CICFlowMeter-compatible synthetic feature generation
# ---------------------------------------------------------------------------

def synthetic_features():
    """
    Generate a complete model feature vector.

    The trained model contains 83 CICFlowMeter/CICDDoS2019 features.
    Every feature expected by the artifact is populated.

    IMPORTANT:
    This remains a synthetic demonstration source. It is not equivalent
    to extracting a real network flow through CICFlowMeter.
    """

    burst = bool(stream_state["attack_burst"])

    # Attack probability increases significantly during burst mode.
    attack_probability = 0.92 if burst else 0.18
    attack = rng.random() < attack_probability

    # ------------------------------------------------------------------
    # Base traffic profile
    # ------------------------------------------------------------------

    if attack:
        protocol = rng.choice([6, 17])  # TCP / UDP
        src_port = rng.randrange(1024, 65535)
        dst_port = rng.choice([53, 80, 443, 123, 1900])

        duration = rng.uniform(20.0, 2500.0)

        pps = rng.uniform(20_000.0, 180_000.0)
        avg_packet = rng.uniform(48.0, 1100.0)

        total_packets = max(
            2.0,
            pps * duration / 1000.0,
        )

        fwd_ratio = rng.uniform(0.72, 0.99)

        total_fwd = max(1.0, total_packets * fwd_ratio)
        total_bwd = max(1.0, total_packets - total_fwd)

        fwd_mean = rng.uniform(40.0, 900.0)
        bwd_mean = rng.uniform(40.0, 900.0)

        total_fwd_bytes = total_fwd * fwd_mean
        total_bwd_bytes = total_bwd * bwd_mean

        syn_count = (
            rng.uniform(20.0, 500.0)
            if protocol == 6
            else 0.0
        )

        ack_count = (
            rng.uniform(0.0, max(1.0, total_fwd * 0.12))
            if protocol == 6
            else 0.0
        )

        psh_count = rng.uniform(0.0, max(1.0, total_packets * 0.08))

        fin_count = rng.uniform(
            0.0,
            max(1.0, total_packets * 0.01),
        )

        rst_count = rng.uniform(
            0.0,
            max(1.0, total_packets * 0.04),
        )

        inbound = rng.choice([0.0, 1.0])

    else:
        protocol = rng.choice([6, 17])
        src_port = rng.randrange(1024, 65535)
        dst_port = rng.choice([22, 53, 80, 443, 3389])

        duration = rng.uniform(100.0, 180_000.0)

        pps = rng.uniform(10.0, 2500.0)
        avg_packet = rng.uniform(60.0, 1400.0)

        total_packets = max(
            2.0,
            pps * duration / 1000.0,
        )

        fwd_ratio = rng.uniform(0.45, 0.65)

        total_fwd = max(1.0, total_packets * fwd_ratio)
        total_bwd = max(1.0, total_packets - total_fwd)

        fwd_mean = rng.uniform(80.0, 1200.0)
        bwd_mean = rng.uniform(60.0, 1200.0)

        total_fwd_bytes = total_fwd * fwd_mean
        total_bwd_bytes = total_bwd * bwd_mean

        syn_count = (
            rng.uniform(0.0, 3.0)
            if protocol == 6
            else 0.0
        )

        ack_count = (
            rng.uniform(0.0, max(1.0, total_packets * 0.35))
            if protocol == 6
            else 0.0
        )

        psh_count = rng.uniform(
            0.0,
            max(1.0, total_packets * 0.03),
        )

        fin_count = rng.uniform(
            0.0,
            max(0.0, total_packets * 0.02),
        )

        rst_count = rng.uniform(
            0.0,
            max(0.0, total_packets * 0.01),
        )

        inbound = rng.choice([0.0, 1.0])

    total_packets = total_fwd + total_bwd

    bps = (
        total_fwd_bytes + total_bwd_bytes
    ) / max(duration / 1000.0, 0.001)

    actual_pps = total_packets / max(duration / 1000.0, 0.001)

    # ------------------------------------------------------------------
    # Build every feature expected by the trained artifact
    # ------------------------------------------------------------------

    features = {}

    for name in detector.feature_names:
        features[name] = 0.0

    def put(name: str, value: float):
        # Model feature names from CICDDoS2019 may have leading spaces.
        if name in features:
            features[name] = _safe(value)
        elif f" {name}" in features:
            features[f" {name}"] = _safe(value)

    # Flow identity
    put("Source Port", src_port)
    put("Destination Port", dst_port)
    put("Protocol", protocol)

    # Core flow
    put("Flow Duration", duration)
    put("Total Fwd Packets", total_fwd)
    put("Total Backward Packets", total_bwd)
    put("Total Length of Fwd Packets", total_fwd_bytes)
    put("Total Length of Bwd Packets", total_bwd_bytes)

    # Packet lengths
    fwd_max = max(fwd_mean, rng.uniform(fwd_mean, max(fwd_mean, 1500.0)))
    bwd_max = max(bwd_mean, rng.uniform(bwd_mean, max(bwd_mean, 1500.0)))

    put("Fwd Packet Length Max", fwd_max)
    put("Fwd Packet Length Min", max(1.0, fwd_mean * 0.25))
    put("Fwd Packet Length Mean", fwd_mean)
    put("Fwd Packet Length Std", abs(fwd_max - fwd_mean) * 0.35)

    put("Bwd Packet Length Max", bwd_max)
    put("Bwd Packet Length Min", max(1.0, bwd_mean * 0.25))
    put("Bwd Packet Length Mean", bwd_mean)
    put("Bwd Packet Length Std", abs(bwd_max - bwd_mean) * 0.35)

    # Rates
    put("Flow Bytes/s", bps)
    put("Flow Packets/s", actual_pps)

    # Inter-arrival times
    flow_iat_mean = 1000.0 / max(actual_pps, 0.001)

    put("Flow IAT Mean", flow_iat_mean)
    put("Flow IAT Std", flow_iat_mean * rng.uniform(0.1, 1.5))
    put("Flow IAT Max", flow_iat_mean * rng.uniform(2.0, 15.0))
    put("Flow IAT Min", max(0.0, flow_iat_mean * rng.uniform(0.01, 0.5)))

    fwd_iat_total = duration * rng.uniform(0.5, 1.0)
    bwd_iat_total = duration * rng.uniform(0.5, 1.0)

    put("Fwd IAT Total", fwd_iat_total)
    put("Fwd IAT Mean", fwd_iat_total / max(total_fwd, 1.0))
    put("Fwd IAT Std", fwd_iat_total * 0.03)
    put("Fwd IAT Max", fwd_iat_total * 0.1)
    put("Fwd IAT Min", 0.0)

    put("Bwd IAT Total", bwd_iat_total)
    put("Bwd IAT Mean", bwd_iat_total / max(total_bwd, 1.0))
    put("Bwd IAT Std", bwd_iat_total * 0.03)
    put("Bwd IAT Max", bwd_iat_total * 0.1)
    put("Bwd IAT Min", 0.0)

    # TCP flags
    put("Fwd PSH Flags", psh_count * 0.6)
    put("Bwd PSH Flags", psh_count * 0.4)
    put("Fwd URG Flags", 0.0)
    put("Bwd URG Flags", 0.0)

    # Header lengths
    fwd_header = total_fwd * (20.0 if protocol == 6 else 8.0)
    bwd_header = total_bwd * (20.0 if protocol == 6 else 8.0)

    put("Fwd Header Length", fwd_header)
    put("Bwd Header Length", bwd_header)

    put(
        "Fwd Packets/s",
        total_fwd / max(duration / 1000.0, 0.001),
    )

    put(
        "Bwd Packets/s",
        total_bwd / max(duration / 1000.0, 0.001),
    )

    # Packet aggregates
    packet_min = min(
        max(1.0, fwd_mean * 0.25),
        max(1.0, bwd_mean * 0.25),
    )

    packet_max = max(fwd_max, bwd_max)

    packet_mean = (
        total_fwd_bytes + total_bwd_bytes
    ) / max(total_packets, 1.0)

    put("Min Packet Length", packet_min)
    put("Max Packet Length", packet_max)
    put("Packet Length Mean", packet_mean)
    put("Packet Length Std", packet_mean * rng.uniform(0.15, 0.65))
    put("Packet Length Variance", packet_mean ** 2 * rng.uniform(0.05, 0.5))

    # Flags
    put("FIN Flag Count", fin_count)
    put("SYN Flag Count", syn_count)
    put("RST Flag Count", rst_count)
    put("PSH Flag Count", psh_count)
    put("ACK Flag Count", ack_count)
    put("URG Flag Count", 0.0)
    put("CWE Flag Count", 0.0)
    put("ECE Flag Count", 0.0)

    # Ratios
    put(
        "Down/Up Ratio",
        total_bwd / max(total_fwd, 1.0),
    )

    put(
        "Average Packet Size",
        packet_mean,
    )

    put(
        "Avg Fwd Segment Size",
        fwd_mean,
    )

    put(
        "Avg Bwd Segment Size",
        bwd_mean,
    )

    # Duplicate CICFlowMeter header field
    put(
        "Fwd Header Length.1",
        fwd_header,
    )

    # Bulk features
    put(
        "Fwd Avg Bytes/Bulk",
        total_fwd_bytes / max(total_fwd, 1.0),
    )

    put(
        "Fwd Avg Packets/Bulk",
        total_fwd / max(1.0, duration / 1000.0),
    )

    put(
        "Fwd Avg Bulk Rate",
        bps * 0.5,
    )

    put(
        "Bwd Avg Bytes/Bulk",
        total_bwd_bytes / max(total_bwd, 1.0),
    )

    put(
        "Bwd Avg Packets/Bulk",
        total_bwd / max(1.0, duration / 1000.0),
    )

    put(
        "Bwd Avg Bulk Rate",
        bps * 0.5,
    )

    # Subflow
    put("Subflow Fwd Packets", total_fwd)
    put("Subflow Fwd Bytes", total_fwd_bytes)
    put("Subflow Bwd Packets", total_bwd)
    put("Subflow Bwd Bytes", total_bwd_bytes)

    # TCP window
    if protocol == 6:
        if attack:
            put("Init_Win_bytes_forward", rng.uniform(0, 65535))
            put("Init_Win_bytes_backward", rng.uniform(0, 65535))
        else:
            put("Init_Win_bytes_forward", rng.uniform(4096, 65535))
            put("Init_Win_bytes_backward", rng.uniform(4096, 65535))

    put(
        "act_data_pkt_fwd",
        total_fwd * rng.uniform(0.3, 0.95),
    )

    # Keep this positive because the current trained artifact contains
    # suspicious negative overflowed values for this feature.
    put(
        "min_seg_size_forward",
        rng.uniform(20.0, 60.0),
    )

    # Active/idle
    if attack:
        active_mean = rng.uniform(1.0, 1000.0)
        idle_mean = rng.uniform(0.0, 100.0)
    else:
        active_mean = rng.uniform(10.0, 10_000.0)
        idle_mean = rng.uniform(100.0, 60_000.0)

    put("Active Mean", active_mean)
    put("Active Std", active_mean * 0.25)
    put("Active Max", active_mean * 2.0)
    put("Active Min", active_mean * 0.1)

    put("Idle Mean", idle_mean)
    put("Idle Std", idle_mean * 0.25)
    put("Idle Max", idle_mean * 2.0)
    put("Idle Min", idle_mean * 0.1)

    # Direction
    put("Inbound", inbound)

    # ------------------------------------------------------------------
    # Fill any remaining artifact features using training statistics.
    # ------------------------------------------------------------------

    for name in detector.feature_names:
        value = features.get(name, 0.0)

        if value == 0.0 and name not in {
            "Fwd URG Flags",
            "Bwd URG Flags",
            "URG Flag Count",
            "CWE Flag Count",
            "ECE Flag Count",
        }:
            # Use the training median as a safe fallback.
            median = _stat(name, "median", 0.0)
            if math.isfinite(median):
                features[name] = max(0.0, median)

    # Compatibility fields used by the dashboard.
    features["pps"] = actual_pps
    features["bps"] = bps

    return features, attack


# ---------------------------------------------------------------------------
# Event creation
# ---------------------------------------------------------------------------

def make_event():
    features, truth = synthetic_features()

    started = time.perf_counter()

    label, p, conf, severity, signals, mode = detector.predict(features)

    elapsed = time.perf_counter() - started

    INFERENCE.observe(elapsed)
    latency_ms.append(elapsed * 1000)

    drift_signals = drift.update(
        features,
        detector.feature_stats,
    )

    signals += [
        {
            "feature": x["feature"],
            "importance": 0.0,
            "value": x["value"],
            "drift_z": x["z_score"],
        }
        for x in drift_signals
    ]

    if mode == "demo" and accuracy:
        accuracy.update(
            truth,
            label == "DDoS",
        )

    src = str(
        ipaddress.IPv4Address(
            rng.randrange(
                0x0A000001,
                0x0AFFFFFF,
            )
        )
    )

    dst = "10.0.0.10"

    event = FlowEvent(
        event_id=uuid.uuid4().hex,
        timestamp=datetime.now(timezone.utc),
        src_ip=src,
        dst_ip=dst,
        src_port=rng.randrange(1024, 65535),
        dst_port=int(features.get("Destination Port", features.get(" Destination Port", 0))),
        protocol=(
            "TCP"
            if int(features.get("Protocol", features.get(" Protocol", 0))) == 6
            else "UDP"
        ),
        label=label,
        probability=p,
        confidence=conf,
        severity=severity,
        bytes_per_second=float(features.get("bps", 0.0)),
        packets_per_second=float(features.get("pps", 0.0)),
        flow_duration_ms=float(features.get("Flow Duration", features.get(" Flow Duration", 0.0))),
        mode=mode,
        model_version=detector.version,
        features=features,
        top_signals=signals,
    )

    return event, truth


# ---------------------------------------------------------------------------
# WebSocket broadcasting
# ---------------------------------------------------------------------------

async def broadcast_event(event: FlowEvent):
    WS_CLIENTS.set(len(clients))

    payload = event.model_dump(mode="json")

    dead = []

    for ws in list(clients):
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)

    for ws in dead:
        clients.discard(ws)


# ---------------------------------------------------------------------------
# Stream loop
# ---------------------------------------------------------------------------

async def stream_loop(stop_event):
    while not stop_event.is_set():

        if stream_state["running"]:

            event, _truth = make_event()

            insert_event(event)

            alert_id = upsert_alert(event)

            stream_state["events"] += 1

            stream_state["last_event_at"] = event.timestamp.isoformat()

            STREAM_EVENTS.set(
                stream_state["events"]
            )

            EVENTS.labels(
                event.label,
                event.mode,
            ).inc()

            DRIFT.set(
                drift.snapshot()["anomaly_rate"]
            )

            if alert_id:
                ALERTS.labels(
                    event.severity
                ).inc()

            await broadcast_event(event)

        await asyncio.sleep(
            max(
                0.01,
                stream_state["interval_ms"] / 1000.0,
            )
        )
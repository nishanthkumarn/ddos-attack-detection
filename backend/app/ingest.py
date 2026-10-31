from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import uuid

from .model import detector
from .schemas import FlowIngestRequest, FlowEvent


def ingest_flow(req: FlowIngestRequest) -> FlowEvent:
    label, probability, confidence, severity, signals, mode = detector.predict(req.features)
    src = str(ipaddress.ip_address(req.src_ip))
    dst = str(ipaddress.ip_address(req.dst_ip))
    return FlowEvent(
        event_id=uuid.uuid4().hex,
        timestamp=req.timestamp or datetime.now(timezone.utc),
        src_ip=src,
        dst_ip=dst,
        src_port=req.src_port,
        dst_port=req.dst_port,
        protocol=req.protocol,
        label=label,
        probability=probability,
        confidence=confidence,
        severity=severity,
        bytes_per_second=float(req.features.get("Flow Bytes/s", req.features.get("bps", 0.0))),
        packets_per_second=float(req.features.get("Flow Packets/s", req.features.get("pps", 0.0))),
        flow_duration_ms=float(req.features.get("Flow Duration", 0.0)),
        mode=mode,
        model_version=detector.version,
        features=req.features,
        top_signals=signals,
    )

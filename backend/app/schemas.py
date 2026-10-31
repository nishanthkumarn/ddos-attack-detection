from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field, ConfigDict


class PredictionRequest(BaseModel):
    features: dict[str, float] = Field(min_length=1)


class PredictionResponse(BaseModel):
    label: str
    probability: float
    confidence: float
    threshold: float
    severity: str
    model_version: str
    mode: str
    top_signals: list[dict[str, Any]] = Field(default_factory=list)
    request_id: str | None = None


class FlowIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timestamp: datetime | None = None
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str = Field(min_length=1, max_length=16)
    features: dict[str, float] = Field(min_length=1)


class FlowEvent(BaseModel):
    event_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    label: str
    probability: float
    confidence: float
    severity: str
    bytes_per_second: float
    packets_per_second: float
    flow_duration_ms: float
    mode: str
    model_version: str
    features: dict[str, float] = Field(default_factory=dict)
    top_signals: list[dict[str, Any]] = Field(default_factory=list)


class StreamCommand(BaseModel):
    action: str
    rate_ms: int | None = Field(default=None, ge=50, le=10000)


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_version: str
    mode: str
    database: str
    stream_clients: int


class ScanRequest(BaseModel):
    src_ip: str = "185.220.101.5"
    dst_ip: str = "10.0.0.10"
    src_port: int = Field(default=44921, ge=0, le=65535)
    dst_port: int = Field(default=80, ge=0, le=65535)
    protocol: str = "TCP"
    packets_per_second: float = 75000.0
    bytes_per_second: float = 40000000.0
    flow_duration_ms: float = 500.0
    total_fwd_packets: float = 37500.0
    total_bwd_packets: float = 0.0
    packet_length_mean: float = 533.0
    syn_flag_count: float = 100.0
    ack_flag_count: float = 0.0
    rst_flag_count: float = 0.0
    psh_flag_count: float = 0.0
    fin_flag_count: float = 0.0
    custom_features: dict[str, float] = Field(default_factory=dict)


class TrainRequest(BaseModel):
    sample_rows: int = Field(default=25000, ge=2000, le=500000)
    max_iter: int = Field(default=100, ge=20, le=500)

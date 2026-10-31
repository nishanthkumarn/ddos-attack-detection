from __future__ import annotations

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from .config import settings
from .batch_eval import MAX_BATCH_UPLOAD_BYTES, evaluate_labeled_csv
from .db import init_db, stats, recent_events, recent_alerts, timeline, insert_event, upsert_alert, insert_scan, recent_scans, get_scan
from .ingest import ingest_flow
from .metrics import metrics_response, WS_CLIENTS
from .model import detector
from .rate_limit import ingest_limiter, predict_limiter
from .schemas import PredictionRequest, PredictionResponse, StreamCommand, HealthResponse, FlowIngestRequest, ScanRequest, TrainRequest
from .security import require_api_key
from .stream import clients, stream_loop, stream_state, drift, broadcast_event
from .trainer import start_background_training, get_status

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("ddos-soc")
stop_event = asyncio.Event()
task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global task
    init_db()
    stop_event.clear()
    task = asyncio.create_task(stream_loop(stop_event))
    log.info("DDoS detection engine started; model_loaded=%s version=%s", detector.loaded, detector.version)
    yield
    stop_event.set()
    if task:
        await task
    log.info("DDoS detection engine stopped")


app = FastAPI(
    title=settings.app_name,
    version="4.0.0",
    lifespan=lifespan,
    description="Defensive real-time DDoS flow detection and SOC telemetry API.",
    docs_url="/docs",
    redoc_url="/redoc",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_observability(request: Request, call_next):
    request_id = request.headers.get("x-request-id", uuid.uuid4().hex)
    started = time.perf_counter()
    response = await call_next(request)
    response.headers["x-request-id"] = request_id
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["x-frame-options"] = "DENY"
    response.headers["cache-control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
    log.info("request id=%s method=%s path=%s status=%s latency_ms=%.2f", request_id, request.method, request.url.path, response.status_code, (time.perf_counter()-started)*1000)
    return response


@app.get("/health", response_model=HealthResponse, tags=["operations"])
def health():
    return {"status": "ok", "model_loaded": detector.loaded, "model_version": detector.version,
            "mode": "model" if detector.loaded else "demo", "database": "postgres" if settings.database_url else "sqlite",
            "stream_clients": len(clients)}


@app.get("/ready", tags=["operations"])
def ready():
    if not detector.loaded and settings.require_trained_model:
        raise HTTPException(503, "trained model is not loaded")
    return {"ready": True, "model_loaded": detector.loaded, "version": detector.version}


@app.get("/metrics", tags=["operations"])
def prometheus_metrics():
    data, content_type = metrics_response()
    return Response(content=data, media_type=content_type)


@app.get("/api/stats", tags=["telemetry"])
def api_stats():
    total, attacks, benign, rate, pps, bps = stats()
    return {"total": total, "attacks": attacks, "benign": benign, "attack_rate": rate, "pps": pps, "bps": bps,
            "model_loaded": detector.loaded, "model_version": detector.version,
            "mode": "model" if detector.loaded else "demo", "stream": stream_state, "drift": drift.snapshot()}


@app.get("/api/events", tags=["telemetry"])
def events(limit: int = 50):
    return recent_events(min(max(limit, 1), 500))


@app.get("/api/alerts", tags=["telemetry"])
def alerts(limit: int = 50):
    return recent_alerts(min(max(limit, 1), 500))


@app.get("/api/timeline", tags=["telemetry"])
def api_timeline(minutes: int = 30):
    return timeline(min(max(minutes, 1), 1440))


@app.get("/api/model", tags=["model"])
def model_info():
    return {"loaded": detector.loaded, "version": detector.version, "threshold": detector.threshold,
            "features": detector.feature_names, "metrics": detector.metrics, "importance": detector.importance[:20],
            "feature_stats": detector.feature_stats, "training": detector.training,
            "contract": {"source": "CICDDoS2019 / CICFlowMeter", "positive_class": "DDoS", "negative_class": "BENIGN"}}


@app.post("/api/scan", tags=["detection"])
def run_scan(req: ScanRequest):
    report = detector.scan_flow(req.model_dump())
    insert_scan(report)
    return report


@app.get("/api/scans", tags=["detection"])
def list_scans(limit: int = 20):
    return recent_scans(min(max(limit, 1), 100))


@app.get("/api/scans/{scan_id}", tags=["detection"])
def fetch_scan(scan_id: str):
    rep = get_scan(scan_id)
    if not rep:
        raise HTTPException(404, "Scan report not found")
    return rep


@app.post("/api/evaluate/csv", tags=["detection"])
async def evaluate_csv(file: UploadFile = File(...)):
    if not detector.loaded:
        raise HTTPException(503, "A trained model must be loaded before CSV evaluation.")
    if file.filename and not file.filename.lower().endswith(".csv"):
        raise HTTPException(415, "Upload a CICFlowMeter-compatible .csv file.")
    content = await file.read(MAX_BATCH_UPLOAD_BYTES + 1)
    await file.close()
    try:
        return evaluate_labeled_csv(content, file.filename or "flows.csv", detector)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/api/model/train", tags=["model"])
def trigger_training(req: TrainRequest):
    start_background_training(sample_rows=req.sample_rows, max_iter=req.max_iter)
    return get_status()


@app.get("/api/model/train/status", tags=["model"])
def training_status_endpoint():
    return get_status()


@app.post("/api/model/reload", tags=["model"])
def reload_model():
    detector.load()
    return {"loaded": detector.loaded, "version": detector.version, "threshold": detector.threshold}


@app.get("/api/security", tags=["operations"])
def security_info():
    return {"authentication": "API key required for state-changing/operator endpoints" if settings.api_key else "development-open",
            "rate_limits": {"predict_per_minute": predict_limiter.limit, "ingest_per_minute": ingest_limiter.limit},
            "telemetry": "Prometheus /metrics"}


@app.post("/api/predict", response_model=PredictionResponse, tags=["detection"])
def predict(req: PredictionRequest, request: Request):
    client = request.client.host if request.client else "unknown"
    if not predict_limiter.allow(client):
        raise HTTPException(429, "prediction rate limit exceeded")
    label, p, conf, severity, signals, mode = detector.predict(req.features)
    return {"label": label, "probability": p, "confidence": conf, "threshold": detector.threshold, "severity": severity,
            "model_version": detector.version, "mode": mode, "top_signals": signals, "request_id": request.headers.get("x-request-id")}


@app.post("/api/ingest", dependencies=[Depends(require_api_key)], tags=["detection"])
async def ingest(req: FlowIngestRequest, request: Request):
    client = request.client.host if request.client else "unknown"
    if not ingest_limiter.allow(client):
        raise HTTPException(429, "ingest rate limit exceeded")
    event = ingest_flow(req)
    insert_event(event)
    alert_id = upsert_alert(event)
    await broadcast_event(event)
    return {"event": event.model_dump(mode="json"), "alert_id": alert_id}


@app.post("/api/stream/control", dependencies=[Depends(require_api_key)], tags=["operations"])
def stream_control(cmd: StreamCommand):
    if cmd.action not in {"start", "stop", "burst"}:
        raise HTTPException(400, "action must be start, stop, or burst")
    stream_state["running"] = cmd.action != "stop"
    stream_state["attack_burst"] = cmd.action == "burst"
    if cmd.rate_ms is not None:
        stream_state["interval_ms"] = cmd.rate_ms
    return stream_state


@app.websocket("/ws/stream")
async def websocket(ws: WebSocket):
    # Browsers cannot reliably attach custom headers to a native WebSocket.
    # If API_KEY is configured, accept ?api_key=... for this local SOC channel.
    supplied = ws.query_params.get("api_key", "")
    if settings.api_key and (not supplied or supplied != settings.api_key):
        await ws.close(code=1008, reason="API key required")
        return
    await ws.accept()
    clients.add(ws)
    WS_CLIENTS.set(len(clients))
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        clients.discard(ws)
    except Exception:
        clients.discard(ws)
    finally:
        WS_CLIENTS.set(len(clients))

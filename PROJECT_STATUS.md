# Project Status — Advanced v4

## Completed

- End-to-end repository scaffold.
- CICDDoS2019 chunked ingestion and validation.
- Leakage-aware grouped train/validation/test splitting with safe fallback.
- Calibrated HistGradientBoosting classifier.
- Validation threshold selection and untouched test evaluation.
- Stored model card, metrics, feature statistics and permutation importance.
- Explicit BENIGN=0 / DDoS=1 semantics.
- FastAPI REST + WebSocket service.
- Protected `/api/ingest` and `/api/stream/control` endpoints.
- Stateless prediction rate limiting.
- Request IDs and security response headers.
- SQLite and PostgreSQL storage modes.
- Five-tuple alert correlation.
- Drift monitoring.
- CSV replay.
- CICFlowMeter wrapper for PCAP/interface → CSV.
- Offline replay evaluation.
- Prometheus metrics.
- Grafana provisioned dashboard.
- React/TypeScript cyber-SOC dashboard.
- Docker Compose deployment topology.
- GitHub Actions CI.
- Python compile/test validation.

## Local validation performed

```text
Python compileall: PASS
pytest: 3 passed
Training split smoke test: PASS
```

Ruff and the frontend build require the project dependencies to be installed in the target environment; this build environment did not contain Ruff/node_modules.

## Important model limitation

The project is only training-valid for features generated in the same way as the CICDDoS2019/CICFlowMeter data. Raw packets are not directly equivalent to flow features. Use the included CICFlowMeter-compatible wrapper/replay path for a realistic demonstration.

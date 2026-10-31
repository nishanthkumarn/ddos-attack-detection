# DDoS Attack Detection in Real Time — Advanced SOC Lab

This repository is a defensive research/education platform for classifying network-flow telemetry as **BENIGN** or **DDoS** and visualizing detections in real time.

## Advanced architecture

```text
CICDDoS2019 / CICFlowMeter CSV
              │
              ▼
     chunked validation + training
              │
              ▼
     calibrated ML detector artifact
              │
      ┌───────┴────────┐
      │                │
CSV replay        PCAP approximation
      │                │
      └───────┬────────┘
              ▼
       FastAPI inference
              │
     ┌────────┼───────────┐
     ▼        ▼           ▼
 WebSocket  SQLite/PG   Prometheus
     │        │           │
     └──────┬─┘           ▼
            ▼          Grafana
       SOC dashboard
```

## Important feature-parity rule

The model is trained on CICFlowMeter-style flow features. **CSV replay from CICDDoS2019 is the parity path.** The included PCAP adapter is intentionally labelled `pcap_approximation`; it demonstrates packet-to-flow plumbing but does not claim exact CICFlowMeter parity. For a research-grade live deployment, run the same CICFlowMeter version/configuration used to produce the training features and feed its CSV/stream into the inference service.

## Run locally

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
cd frontend
npm install
cd ..
```

Put CICDDoS2019 CSV files in `data/raw/`, then:

```powershell
python backend\scripts\prepare.py
python backend\scripts\train.py
```

Start:

```powershell
cd backend
python -m uvicorn app.main:app --reload --port 8000
```

In another terminal:

```powershell
cd frontend
npm run dev
```

## Replay a real dataset CSV

```powershell
$env:PYTHONPATH="backend"
python backend\scripts\replay_csv.py data\raw\YOUR_FILE.csv --rate 20 --limit 1000
```

## PCAP lab replay

```powershell
$env:PYTHONPATH="backend"
python backend\scripts\replay_pcap.py sample.pcap --interval 0.05 --max-packets 5000
```

Again, use CICFlowMeter-generated CSV for model-comparable experiments.

## Production-style Docker lab

```powershell
docker compose up --build
```

Services:

- SOC UI: `http://localhost:8080`
- API/docs: `http://localhost:8000/docs`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`
- PostgreSQL: internal Docker network
- Redis: internal Docker network

The Docker deployment sets an example operator API key. Change it before any non-lab use.

## Observability

`GET /metrics` exports:

- processed event counters
- DDoS alert counters
- inference latency histogram
- WebSocket client gauge
- stream event gauge
- rolling feature-drift rate

## Security model

State-changing stream controls require `X-API-Key` when `API_KEY` is configured. Keep the dashboard/API behind TLS, an authenticated reverse proxy, and a restricted network for any deployment beyond a local lab.

## Evaluation

The training pipeline reports ROC-AUC, average precision, precision, recall and F1 at the selected operating threshold. Do not use a random row split as the sole evidence of real-world performance: CICDDoS2019 contains correlated traffic captures. For stronger evaluation, split by capture/day/attack scenario and report per-family results.

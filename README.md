# DDoS Attack Detection in Real Time — CyberLab SOC-X

An advanced defensive ML/SOC platform for classifying **CICFlowMeter-compatible network flows** as **BENIGN** or **DDoS**, with replay, streaming inference, alert correlation, drift telemetry and observability.

## What makes this version advanced

- CICDDoS2019-aware training pipeline with chunked CSV processing.
- Grouped file-aware train/validation/test splitting to reduce dataset leakage where enough source files exist.
- Explicit `BENIGN=0`, `DDoS=1` semantics.
- Median imputation + schema locking.
- HistGradientBoosting + sigmoid probability calibration.
- Validation threshold selection with a configurable minimum-recall target.
- Untouched test metrics: ROC-AUC, average precision, Brier score, precision, recall, F1 and confusion matrix.
- Permutation-based feature importance and stored training metadata.
- Real `/api/ingest` endpoint for extracted flow records.
- WebSocket real-time SOC feed.
- Synthetic attack-burst simulator for safe demonstrations.
- CSV replay and CICFlowMeter wrapper for PCAP/interface → flow CSV → API workflows.
- Correlated alerts keyed by 5-tuple.
- Unlabeled feature-drift telemetry.
- SQLite WAL for local mode and PostgreSQL for deployment mode.
- Optional Redis service reserved for multi-worker/event-bus expansion.
- Prometheus metrics + pre-provisioned Grafana dashboard.
- API-key protection and basic rate limiting.
- Health/readiness endpoints and request IDs.
- Docker Compose stack and GitHub Actions CI.

## Data contract

The model is trained on **flow features**, not raw packets. The real-world path is:

```text
PCAP / authorized interface
        ↓
CICFlowMeter-compatible flow extraction
        ↓
CSV flow features
        ↓
/api/ingest
        ↓
ML model
        ↓
alert correlation
        ↓
SOC dashboard + Prometheus/Grafana
```

The official CICFlowMeter repository describes CICFlowMeter as a bidirectional flow generator/analyzer used for CICDDoS2019 and documents offline PCAP and interface capture workflows. Use the same feature-generation methodology used by the training data for meaningful parity. urlCICFlowMeter repositoryhttps://github.com/ahlashkari/CICFlowMeter

A maintained Python CICFlowMeter-compatible implementation documents `-f` for PCAP input and `-i` for interface capture. urlPython CICFlowMeter implementationhttps://github.com/hieulw/cicflowmeter

## Local setup

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r backend\requirements.txt
```

Frontend:

```powershell
cd frontend
npm install
npm run build
cd ..
```

## Dataset

Place extracted CICDDoS2019 CSV files in:

```text
data/raw/
```

Then:

```powershell
python backend\scripts\prepare.py
python backend\scripts\train.py
```

For a smaller machine, start with:

```powershell
$env:MODEL_SAMPLE_ROWS="100000"
python backend\scripts\train.py
```

The resulting artifact is:

```text
models/ddos_detector.joblib
models/training_report.json
```

## Run

Backend:

```powershell
cd backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Frontend in another terminal:

```powershell
cd frontend
npm run dev
```

Open the Vite URL, normally `http://localhost:5173`.

## Useful endpoints

- `/health` — liveness
- `/ready` — readiness/model gate
- `/docs` — OpenAPI UI
- `/api/stats` — SOC statistics
- `/api/events` — recent flow events
- `/api/alerts` — correlated alerts
- `/api/timeline` — time buckets
- `/api/model` — model card/metadata
- `/api/predict` — stateless prediction
- `/api/evaluate/csv` — evaluate a labeled CICFlowMeter CSV; returns per-flow predictions and aggregate metrics
- `/api/ingest` — flow ingestion; protected when API key is configured
- `/api/stream/control` — start/stop/burst; protected
- `/ws/stream` — live telemetry channel
- `/metrics` — Prometheus exposition

## Real flow replay

After starting the API:

```powershell
$env:API_KEY="your-local-key"
python backend\scripts\replay_csv.py data\processed\flows.csv --api-key $env:API_KEY
```

For PCAP conversion with a compatible extractor:

```powershell
python backend\scripts\run_cicflowmeter.py --pcap capture.pcap --output data\processed\flows.csv
python backend\scripts\replay_csv.py data\processed\flows.csv --api-key $env:API_KEY
```

For labeled offline evaluation without changing the database:

```powershell
python backend\scripts\evaluate_replay.py data\processed\labeled_flows.csv
```

For an interactive batch evaluation, open the dashboard's **Flow Scanner** tab and choose **Labeled CSV test**. Upload a CICFlowMeter-compatible CSV with a `Label`, `Class`, or `Target` column to review per-flow predictions, false positives/negatives, attack-family recall, and aggregate metrics. The upload is processed in memory and is limited to 25 MB and 20,000 flow rows; export the results as JSON or CSV from the page.

For a quick check, upload [`data/sample_labeled_flows.csv`](data/sample_labeled_flows.csv). It contains 5 benign and 5 DDoS DNS flows sampled from the local CICDDoS2019 data, with IP addresses anonymized. This small sample is for verifying the workflow, not for estimating generalization performance.

## Docker SOC stack

```powershell
docker compose up --build
```

Services:

```text
Frontend       http://localhost:8080
FastAPI        http://localhost:8000/docs
Prometheus     http://localhost:9090
Grafana        http://localhost:3000
PostgreSQL     internal
Redis          internal
```

Change development passwords and API keys before using the stack outside localhost.

## Tests

```powershell
make test
make test-e2e
make lint
```

Frontend:

```powershell
cd frontend
npm test
npm run build
```

## Project layout

```text
data/raw/                 CICDDoS2019 CSVs (ignored)
data/processed/           replay/generated flow files
models/                    trained artifacts
backend/app/               API, detector, stream, persistence, security
backend/scripts/           training, replay, evaluation, load tests
backend/tests/             API tests
frontend/src/              SOC dashboard
deploy/                    Nginx, Prometheus, Grafana
configs/                   feature contract
.github/workflows/         CI
```

## Safety and interpretation

This is a defensive research system. A high probability is model evidence, not proof of malicious intent. Dataset-specific artifacts, distribution shift, flash crowds, encrypted traffic and unseen attack families can change performance. Automated blocking should remain a separate, reviewed control plane.

## Frontend TypeScript fix

The frontend includes `src/vite-env.d.ts`, which provides Vite's `ImportMetaEnv` typing. This is required for `import.meta.env.VITE_API_URL` and `import.meta.env.VITE_OPERATOR_API_KEY` to compile with TypeScript.

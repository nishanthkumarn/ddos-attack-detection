# Operations runbook

## Local lab
1. Put CICDDoS2019 CSV files under `data/raw/`.
2. Run `make prepare`.
3. Run `make train`.
4. Start API with `make serve`.
5. Start dashboard with `make dev`.
6. Trigger `ATTACK BURST` in the dashboard.

## PCAP parity path
Install a CICFlowMeter-compatible extractor. The maintained Python CICFlowMeter implementation documents `-f` for offline PCAP and `-i` for interface capture. Then:

```bash
python backend/scripts/run_cicflowmeter.py --pcap capture.pcap --output data/processed/flows.csv
python backend/scripts/replay_csv.py data/processed/flows.csv --api-key "$API_KEY"
```

For online interface capture, run the extractor with appropriate operating-system privileges and only on networks you are authorized to monitor.

## Production topology
Use `docker compose up --build` for PostgreSQL, Redis, API, frontend, Prometheus and Grafana. Change every development credential before exposing anything beyond localhost.

## Incident safety
This project is a detector. It should emit evidence and telemetry; automated traffic blocking should be a separate, reviewed control plane with allowlists, rollback, rate limits and human approval.

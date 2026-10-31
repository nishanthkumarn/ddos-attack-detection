# Architecture

```text
                     +-----------------------+
                     | PCAP / Network IF     |
                     +-----------+-----------+
                                 |
                         CICFlowMeter-compatible
                         bidirectional flow extraction
                                 |
                                 v
+----------------+       +-----------------------+
| CICDDoS2019    |------>| Flow Feature Contract |
| training CSVs  |       +-----------+-----------+
+----------------+                   |
                                     v
                         +-----------------------+
                         | Leakage-aware trainer |
                         | HGB + sigmoid cal.    |
                         | threshold selection   |
                         +-----------+-----------+
                                     |
                              joblib artifact
                                     |
                                     v
                         +-----------------------+
                         | FastAPI Detection API |
                         | /predict /ingest      |
                         +-----------+-----------+
                                     |
                 +-------------------+-------------------+
                 |                   |                   |
                 v                   v                   v
              SQLite/Postgres      Redis*          Prometheus
                 |                                       |
                 +-------------------+-------------------+
                                     v
                              SOC Dashboard
                         React + TypeScript + WS

* Redis is reserved for multi-worker event distribution/caching; local mode works without it.
```

## Trust boundaries

- Training data is untrusted input and is processed with chunked readers.
- State-changing API endpoints require an API key outside development mode.
- WebSocket access also requires the API key when configured.
- The model never receives raw packet bytes; flow extraction is a separate boundary.
- The synthetic generator is explicitly demo data and must not be used as evidence of real-world detection performance.

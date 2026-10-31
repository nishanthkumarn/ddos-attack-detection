# Security notes

This repository is a defensive research/education platform.

- Run it on systems and networks you are authorized to monitor.
- The synthetic attack-burst control generates local test telemetry; it does not generate packets on a network.
- PCAP/interface capture must only be performed with authorization.
- Set a strong `API_KEY` and `REQUIRE_TRAINED_MODEL=true` before exposing the service.
- Keep PostgreSQL, Redis, Prometheus and Grafana bound to a trusted network.
- Do not put secrets, datasets, model artifacts or customer traffic into Git.
- The detector should inform a separate reviewed response control plane rather than directly blocking traffic.

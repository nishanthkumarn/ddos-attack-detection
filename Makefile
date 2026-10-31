PYTHON ?= python
PIP ?= pip

setup:
	$(PIP) install -r backend/requirements.txt

prepare:
	$(PYTHON) backend/scripts/prepare.py

data: prepare

train:
	$(PYTHON) backend/scripts/train.py

serve:
	cd backend && $(PYTHON) -m uvicorn app.main:app --host 0.0.0.0 --port 8000

dev:
	cd frontend && npm run dev

test:
	PYTHONPATH=backend $(PYTHON) -m pytest -q

test-e2e:
	PYTHONPATH=backend $(PYTHON) backend/scripts/e2e.py

load-test:
	PYTHONPATH=backend $(PYTHON) backend/scripts/loadtest.py

lint:
	ruff check backend tests

pcap-replay:
	PYTHONPATH=backend $(PYTHON) backend/scripts/replay_pcap.py $(PCAP)

csv-replay:
	PYTHONPATH=backend $(PYTHON) backend/scripts/replay_csv.py $(CSV)

docker-up:
	docker compose up --build

docker-down:
	docker compose down

observability:
	@echo Prometheus: http://localhost:9090
	@echo Grafana:    http://localhost:3000
	@echo Backend:    http://localhost:8000/docs

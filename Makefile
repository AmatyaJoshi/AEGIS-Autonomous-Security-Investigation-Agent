# AEGIS — thin wrappers. Every target has a plain-command equivalent in README.md for machines
# without make (Windows: run the commands in the recipe by hand or via Git Bash).
.PHONY: install data demo api web up down logs reset test lint

PY ?= .venv/Scripts/python
ifeq (,$(wildcard .venv/Scripts/python.exe))
PY := .venv/bin/python
endif

install:       ## Python venv + deps, web deps
	uv venv --python 3.12 && uv pip install -e ".[dev]"
	cd web && npm install --no-audit --no-fund

data:          ## Datasets -> Parquet -> snapshot -> benchmark -> triage model (~25 min, ~140 MB download, once)
	$(PY) -m aegis.cli lab load --datasets otrf,evtx
	$(PY) -m aegis.cli lab noise --days 14 --per-day 12
	$(PY) -m aegis.cli lab rules
	$(PY) -m aegis.cli bench prepare
	$(PY) -m aegis.cli lab snapshot --name dev
	$(PY) -m aegis.cli bench build
	$(PY) -m training.triage.build_dataset --snapshot dev
	$(PY) -m training.triage.train
	$(PY) -m training.triage.eval

demo:          ## Reset -> investigate 1 TP + 3 FP + 1 ambiguous -> print the URL to open (< 3 min)
	$(PY) -m aegis.cli demo
	@echo "UI  -> http://localhost:3000   (run 'make api' and 'make web' in two terminals)"

api:           ## Review API on :8000 (offline snapshot, SQLite)
	$(PY) -m aegis.cli serve --host 0.0.0.0 --port 8000

web:           ## Review UI on :3000 (dev server)
	cd web && npm run dev

up:            ## Docker: api + web (+ ollama with model pull) in the background
	docker compose -f docker-compose.demo.yml up -d --build
	@echo "web -> http://localhost:3000   api -> http://localhost:8000/docs"

down:          ## Stop the demo stack, keep volumes (data + pulled model)
	docker compose -f docker-compose.demo.yml down

logs:          ## Follow demo stack logs
	docker compose -f docker-compose.demo.yml logs -f --tail=100

reset:         ## Clear the review queue and case memory only (keeps datasets, snapshot, model)
	$(PY) -c "from aegis.api.store import Store; print('cleared', Store().reset_investigations(), 'investigations')"
	rm -f data/memory.db data/memory.pulse_schema.json

test:          ## Gates: ruff, format, mypy (strict, aegis/), pytest, tsc
	$(PY) -m ruff check aegis lab bench training tests
	$(PY) -m ruff format --check aegis lab bench training tests
	$(PY) -m mypy
	$(PY) -m pytest -q
	cd web && npx tsc --noEmit

lint:          ## Lint + format in place
	$(PY) -m ruff check --fix aegis lab bench training tests && $(PY) -m ruff format aegis lab bench training tests

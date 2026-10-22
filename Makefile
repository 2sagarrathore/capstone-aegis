.DEFAULT_GOAL := help
VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

.PHONY: help venv install test lint scan dashboard stack stack-down docker clean demo

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-14s\033[0m %s\n", $$1, $$2}'

venv: ## Create the virtualenv
	python3 -m venv $(VENV) && $(PIP) install --quiet --upgrade pip

install: venv ## Install Aegis and its dev dependencies
	$(PIP) install --quiet -e ".[dev]"

test: ## Run the test suite
	$(VENV)/bin/pytest

scan: ## Scan IMAGE=<ref> (e.g. make scan IMAGE=python:3.12-slim)
	@test -n "$(IMAGE)" || (echo "usage: make scan IMAGE=<reference>" && exit 1)
	$(PY) -m aegis scan $(IMAGE)

dashboard: ## Serve the dashboard on :8080
	$(PY) -m aegis serve --host 127.0.0.1 --port 8080

stack: ## Start dashboard + Prometheus + Grafana
	docker compose up -d --build

stack-down: ## Stop the stack
	docker compose down

docker: ## Build the scanner image
	docker build -t aegis-scanner:1.0.0 .

demo: ## Scan a demo image set and backfill trend history
	$(PY) -m aegis scan python:3.9-slim nginx:1.21 node:16-alpine redis:6.2 ubuntu:22.04 -q || true
	$(PY) scripts/seed_demo_history.py

clean: ## Remove generated artifacts
	rm -rf reports build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

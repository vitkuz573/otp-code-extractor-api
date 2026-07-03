.PHONY: help install dev run test lint format typecheck clean docker-build docker-run docker-stop benchmark coverage qr-sample

PYTHON ?= python
PIP ?= $(PYTHON) -m pip
APP_MODULE := otp_code_extractor.main:app

help:
	@echo "OTP Code Extractor API - make targets"
	@echo "  install       Install runtime dependencies"
	@echo "  dev           Install dev dependencies"
	@echo "  run           Run the API on http://0.0.0.0:8000"
	@echo "  test          Run the pytest suite"
	@echo "  coverage      Run tests with coverage report"
	@echo "  benchmark     Run local performance benchmarks"
	@echo "  lint          Run ruff lint"
	@echo "  format        Run ruff format"
	@echo "  typecheck     Run mypy"
	@echo "  docker-build  Build the Docker image"
	@echo "  docker-run    Start the API via docker compose"
	@echo "  docker-stop   Stop the docker compose stack"
	@echo "  qr-sample     Generate a sample QR PNG for testing"
	@echo "  clean         Remove caches and build artefacts"

install:
	$(PIP) install -r requirements.txt

dev:
	$(PIP) install -r requirements-dev.txt

run:
	uvicorn $(APP_MODULE) --host 0.0.0.0 --port 8000 --reload

test:
	pytest

coverage:
	pytest --cov=otp_code_extractor --cov-report=term-missing

benchmark:
	$(PYTHON) scripts/benchmark.py

lint:
	ruff check src tests

format:
	ruff format src tests

typecheck:
	mypy src

docker-build:
	docker build -t otp-code-extractor-api:local .

docker-run:
	docker compose up -d

docker-stop:
	docker compose down

qr-sample:
	$(PYTHON) scripts/make_qr.py --out data/sample_otp.png

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info __pycache__ htmlcov
	find src tests -type d -name __pycache__ -exec rm -rf {} +

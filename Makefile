.PHONY: help install dev test lint type-check format clean docker-up docker-down migrate seed capture

PYTHON   := python
UVICORN  := uvicorn
PYTEST   := pytest
BLACK    := black
RUFF     := ruff
MYPY     := mypy
ALEMBIC  := alembic

BACKEND_DIR := backend
FRONTEND_DIR := frontend

help:
	@echo "AI Packet Analyzer – available targets"
	@echo "  install        Install all dependencies"
	@echo "  dev            Start backend dev server"
	@echo "  frontend       Start frontend dev server"
	@echo "  test           Run full test suite"
	@echo "  lint           Run ruff linter"
	@echo "  type-check     Run mypy type checker"
	@echo "  format         Auto-format with black + ruff"
	@echo "  migrate        Run alembic migrations"
	@echo "  seed           Seed database with sample data"
	@echo "  docker-up      Start all services via docker-compose"
	@echo "  docker-down    Stop all docker services"
	@echo "  clean          Remove build artefacts"

install:
	cd $(BACKEND_DIR) && pip install -r requirements.txt
	cd $(FRONTEND_DIR) && npm install

dev:
	cd $(BACKEND_DIR) && $(UVICORN) app.main:app --reload --host 0.0.0.0 --port 8000

frontend:
	cd $(FRONTEND_DIR) && npm run dev

test:
	cd $(BACKEND_DIR) && $(PYTEST) tests/ -v --cov=app --cov-report=term-missing --cov-fail-under=80

lint:
	cd $(BACKEND_DIR) && $(RUFF) check app/ tests/

type-check:
	cd $(BACKEND_DIR) && $(MYPY) app/ --ignore-missing-imports

format:
	cd $(BACKEND_DIR) && $(BLACK) app/ tests/ && $(RUFF) check --fix app/ tests/

migrate:
	cd $(BACKEND_DIR) && $(ALEMBIC) upgrade head

migrate-create:
	cd $(BACKEND_DIR) && $(ALEMBIC) revision --autogenerate -m "$(msg)"

seed:
	cd $(BACKEND_DIR) && $(PYTHON) -m app.database.seed

docker-up:
	docker compose -f docker/docker-compose.yml up -d

docker-down:
	docker compose -f docker/docker-compose.yml down

docker-build:
	docker compose -f docker/docker-compose.yml build

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .mypy_cache -exec rm -rf {} +
	find . -type d -name .ruff_cache -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -name "*.pyc" -delete
	rm -rf $(BACKEND_DIR)/htmlcov $(BACKEND_DIR)/.coverage

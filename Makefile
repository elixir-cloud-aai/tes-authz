COMPOSE := docker compose -f compose.yaml
export UV_CACHE_DIR := $(CURDIR)/.cache/uv
export UV_PROJECT_ENVIRONMENT := $(CURDIR)/.venv

.PHONY: test up down logs unit golden lint

## Run everything (lint, types, policy check, services, all suites, cleanup).
test:
	scripts/test.sh

## Start the engines, shims and stub (loopback ports 18080, 18181, 18190-18192).
up:
	$(COMPOSE) up -d --wait

## Stop and remove all containers and the state volume.
down:
	$(COMPOSE) down -v --remove-orphans

logs:
	$(COMPOSE) logs --tail=100

## Unit tests only (no containers).
unit:
	uv run pytest -p no:cacheprovider -m "not services"

## Regenerate the golden files after changing scripts/gen_golden.py.
golden:
	uv run python scripts/gen_golden.py

lint:
	uv run ruff check . && uv run ruff format --check . && uv run mypy shims stub harness tes engines/openfga scripts

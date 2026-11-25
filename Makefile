# TES_AUTHZ_PROJECT and TES_AUTHZ_PORT_BASE select this worktree's stack
# (harness/stack.py); the defaults are the main checkout's.
COMPOSE := eval "$$(python3 harness/stack.py)" && docker compose -p "$$TES_AUTHZ_PROJECT" -f compose.yaml
export UV_CACHE_DIR := $(CURDIR)/.cache/uv
export UV_PROJECT_ENVIRONMENT := $(CURDIR)/.venv

.PHONY: test up down logs unit golden lint kubernetes image

## Run everything (lint, types, policy check, services, all suites, cleanup).
test:
	bash scripts/test.sh

## Start the engines, shims, stub and mock OIDC issuer (default loopback ports 18080, 18181, 18190-18193).
up:
	$(COMPOSE) up -d --wait

## Stop and remove all containers and the state volume.
down:
	$(COMPOSE) down -v --remove-orphans

## Show the last 100 log lines of each service.
logs:
	$(COMPOSE) logs --tail=100

## Deploy deploy/kubernetes/ to the current kubectl context (e.g. kind) and test it.
kubernetes:
	bash scripts/test-kubernetes.sh

## Build the image of Dockerfile (OPA decision service) and test a container of it.
image:
	bash scripts/test-image.sh

## Unit tests only (no containers).
unit:
	uv run pytest -p no:cacheprovider -m "not services"

## Regenerate the golden files after changing scripts/gen_golden.py.
golden:
	uv run python scripts/gen_golden.py

## Lint and format check (ruff), then type check (mypy, paths in pyproject.toml).
lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy

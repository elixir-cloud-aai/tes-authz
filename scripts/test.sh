#!/usr/bin/env bash
# Run everything: lint, type check, unit tests, then the compose services and
# all suites against them; the services are always stopped and removed.
#
# Usage: scripts/test.sh [pytest args...]
#   TES_AUTHZ_KEEP=1     leave the services running afterwards
#   TES_AUTHZ_TES=a,b    TES adapters to run (default: mock)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export UV_CACHE_DIR="$root/.cache/uv"
export UV_PROJECT_ENVIRONMENT="$root/.venv"
export TES_AUTHZ_REQUIRE_SERVICES=1
compose=(docker compose -f "$root/compose.yaml")

cleanup() {
  if [[ "${TES_AUTHZ_KEEP:-0}" != "1" ]]; then
    "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

uv sync --project "$root" --quiet
cd "$root"
uv run --project "$root" ruff check .
uv run --project "$root" ruff format --check .
uv run --project "$root" mypy shims stub harness tes engines/openfga scripts
docker run --rm -v "$root/engines/opa/policy:/policy:ro" openpolicyagent/opa:1.22.4 check --strict /policy
"${compose[@]}" up -d --wait
uv run --project "$root" pytest -p no:cacheprovider "$@"

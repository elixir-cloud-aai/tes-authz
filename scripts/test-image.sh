#!/usr/bin/env bash
# Build the image of `Dockerfile` (the OPA decision service) and test a
# container of it, hardened as in `compose.yaml` (read-only, no
# capabilities, no new privileges): the golden requests against the front
# (`tests/test_image.py`), that OPA answers on the container's loopback only
# and refuses everything but the decision query and the health check, that
# the image has no pip, and that it refuses to start without policy
# data. The container is removed afterwards; the image is kept for the scan.
#
# Usage: scripts/test-image.sh [pytest args...]
#   Needs Docker (with Buildx) and uv.
#   TES_AUTHZ_IMAGE       tag to build (default: tes-authz:test-<checkout
#                         directory>, so that worktrees don't share it)
#   TES_AUTHZ_IMAGE_SKIP_BUILD=1  test an existing image of that tag
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# As in the Makefile, so that the script also runs on its own
export UV_CACHE_DIR="$root/.cache/uv"
export UV_PROJECT_ENVIRONMENT="$root/.venv"
image="${TES_AUTHZ_IMAGE:-tes-authz:test-$(basename "$root" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9_.\n-' '-')}"
container="tes-authz-image-test-$$"
hardening=(--read-only --cap-drop ALL --security-opt no-new-privileges:true)

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ "${TES_AUTHZ_IMAGE_SKIP_BUILD:-0}" != "1" ]]; then
  docker build -t "$image" "$root"
fi

# The API policy of OPA (`engines/opa/system/authz.rego`) passes its tests,
# with the OPA of the image; the tests themselves aren't in the image
docker run --rm --entrypoint opa "${hardening[@]}" \
  -v "$root/engines/opa/system:/system:ro" "$image" \
  test --verbose /system
if docker run --rm --entrypoint sh "$image" -c 'ls /opt/tes-authz/system/*_test.rego' >/dev/null 2>&1; then
  echo "[FAIL] the image has the tests of the API policy" >&2
  exit 1
fi
echo "[ok] API policy tests pass and aren't in the image"

# No installer in the image
if docker run --rm --entrypoint python "$image" -c "import pip" 2>/dev/null; then
  echo "[FAIL] the image has pip" >&2
  exit 1
fi
echo "[ok] no pip in the image"

# Without policy data, the service refuses to start (status 2)
status=0
docker run --rm "${hardening[@]}" "$image" >/dev/null 2>&1 || status=$?
if [[ "$status" != "2" ]]; then
  echo "[FAIL] without policy data the service exited with $status, expected 2" >&2
  exit 1
fi
echo "[ok] refuses to start without policy data"

docker run -d --name "$container" "${hardening[@]}" \
  -p "127.0.0.1::8080" \
  -v "$root/config/reference-policy.json:/etc/tes-authz/data.json:ro" \
  "$image" >/dev/null
# The loopback port that Docker chose, so that parallel runs don't collide
port="$(docker port "$container" 8080/tcp | head -n 1)"
port="${port##*:}"
ready=0
for _ in $(seq 30); do
  if curl -sf "http://127.0.0.1:$port/health" >/dev/null; then
    ready=1
    break
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' "$container")" != "true" ]]; then
    break
  fi
  sleep 1
done
if [[ "$ready" != "1" ]]; then
  echo "[FAIL] front not ready after 30 s:" >&2
  docker logs "$container" >&2 || true
  exit 1
fi

# OPA answers on the container's loopback, but not on its network address
container_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container")"
if [[ -z "$container_ip" ]]; then
  echo "[FAIL] the container has no network address to probe OPA on" >&2
  exit 1
fi
docker exec "$container" python -c "
import sys, urllib.error, urllib.request
urllib.request.urlopen('http://127.0.0.1:8181/health', timeout=5)
try:
    urllib.request.urlopen('http://$container_ip:8181/health', timeout=5)
except urllib.error.HTTPError:
    sys.exit('[FAIL] OPA answers on the container address')
except OSError:
    print('[ok] OPA listens on the container loopback only')
else:
    sys.exit('[FAIL] OPA answers on the container address')
"

# OPA's API answers only the decision query and the health check
# (`engines/opa/system/authz.rego`): no other container of a pod, which
# shares the loopback, can read or replace policy or data
docker exec "$container" python -c "
import sys, urllib.error, urllib.request
base = 'http://127.0.0.1:8181'
for method, path, body in [
    ('PUT', '/v1/policies/x', b'package tes.authz\\nallow := true'),
    ('PUT', '/v1/data/tes_authz', b'{}'),
    ('PATCH', '/v1/data', b'[]'),
    ('GET', '/v1/data', None),
    ('GET', '/v1/policies', None),
    ('POST', '/v1/data/tes_authz', b'{}'),
    # The decision, but with a trace that would show the data
    ('POST', '/v1/data/tes/authz/allow?explain=full', b'{}'),
    ('POST', '/v1/data/tes/authz/allow?provenance&metrics', b'{}'),
]:
    request = urllib.request.Request(base + path, data=body, method=method)
    try:
        urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as exc:
        if exc.code not in (401, 403):
            sys.exit(f'[FAIL] OPA answered {exc.code} to {method} {path}')
    else:
        sys.exit(f'[FAIL] OPA allowed {method} {path}')
print('[ok] OPA refuses changes and reads of policy and data')
"

uv sync --project "$root" --locked --quiet
cd "$root"
if ! TES_AUTHZ_IMAGE_URL="http://127.0.0.1:$port/access/v1/evaluation" \
  uv run --project "$root" pytest -p no:cacheprovider tests/test_image.py "$@"; then
  docker logs --tail=50 "$container" >&2 || true
  exit 1
fi

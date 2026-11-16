#!/usr/bin/env bash
# Create the kind cluster tes-authz-tesk for the TESK adapter, with its
# kubeconfig in the TESK clone (TES_AUTHZ_TESK_KUBECONFIG). TESK API itself
# runs per test (adapter.py) as the container tes-authz-tesk-api.
# Remove both with tes/tesk/down.sh.
set -euo pipefail
dir="${TES_AUTHZ_TESK_DIR:-$HOME/Work/agent-clones/tes-authz-tesk}"
kubeconfig="${TES_AUTHZ_TESK_KUBECONFIG:-$dir/.cache/kind-kubeconfig}"
mkdir -p "$(dirname "$kubeconfig")"
if ! kind get clusters | grep -qx tes-authz-tesk; then
  kind create cluster --name tes-authz-tesk --kubeconfig "$kubeconfig" --wait 120s
fi
kind get kubeconfig --name tes-authz-tesk > "$kubeconfig"

#!/usr/bin/env bash
# Deploy the decision service of `deploy/kubernetes/` to a Kubernetes
# cluster and test it: the golden requests through a port forward, and,
# from client pods (`scripts/k8s_probe.py`), that only pods with the
# NetworkPolicy's label reach the Service and that no pod reaches OPA.
# The namespace is deleted afterwards. Needs a network plugin that enforces
# NetworkPolicies (kind's does).
#
# Usage: scripts/test-kubernetes.sh [pytest args...]
#   Needs kubectl with a context for a disposable cluster, e.g. kind:
#   `kind create cluster --name tes-authz` (CI: helm/kind-action).
#   TES_AUTHZ_K8S_NAMESPACE  namespace to create and delete (default: tes-authz-test)
#   TES_AUTHZ_K8S_PORT       local port of the port forward (default: 18290)
#   TES_AUTHZ_KEEP=1         keep the namespace afterwards
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export UV_CACHE_DIR="$root/.cache/uv"
export UV_PROJECT_ENVIRONMENT="$root/.venv"
namespace="${TES_AUTHZ_K8S_NAMESPACE:-tes-authz-test}"
port="${TES_AUTHZ_K8S_PORT:-18290}"
kube=(kubectl -n "$namespace")
forward_pid=""

cleanup() {
  if [[ -n "$forward_pid" ]]; then
    kill "$forward_pid" 2>/dev/null || true
  fi
  if [[ "${TES_AUTHZ_KEEP:-0}" != "1" ]]; then
    kubectl delete namespace "$namespace" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

kubectl create namespace "$namespace"
# The three ConfigMaps of the manifest, from this checkout; the data is the
# reference policy, which the golden expectations are written for
"${kube[@]}" create configmap tes-authz-policy --from-file="$root/engines/opa/policy/tes_authz.rego"
"${kube[@]}" create configmap tes-authz-shims \
  --from-file="$root/shims/common.py" --from-file="$root/shims/opa_front.py"
"${kube[@]}" create configmap tes-authz-data --from-file=data.json="$root/config/reference-policy.json"
"${kube[@]}" apply -f "$root/deploy/kubernetes/tes-authz.yaml"
if ! "${kube[@]}" rollout status deployment/tes-authz --timeout=180s; then
  "${kube[@]}" describe pods -l app.kubernetes.io/name=tes-authz
  "${kube[@]}" logs deployment/tes-authz --all-containers --tail=50 || true
  exit 1
fi

# Network checks from client pods (scripts/k8s_probe.py, on stdin), with the
# front's image: with the NetworkPolicy's label, a client reaches the
# Service; without it, it doesn't; neither reaches OPA on the pod IP
pod_ip="$("${kube[@]}" get pods -l app.kubernetes.io/name=tes-authz -o jsonpath='{.items[0].status.podIP}')"
image="$("${kube[@]}" get deployment tes-authz \
  -o jsonpath='{.spec.template.spec.containers[?(@.name=="opa-front")].image}')"
"${kube[@]}" run tes-authz-client --image="$image" --restart=Never --rm -i --quiet \
  --labels=tes-authz/client=true --command -- python - labelled "$pod_ip" <"$root/scripts/k8s_probe.py"
"${kube[@]}" run tes-authz-other --image="$image" --restart=Never --rm -i --quiet \
  --command -- python - unlabelled "$pod_ip" <"$root/scripts/k8s_probe.py"

"${kube[@]}" port-forward service/tes-authz "$port:8080" >/dev/null &
forward_pid=$!
for _ in $(seq 30); do
  if curl -sf "http://127.0.0.1:$port/health" >/dev/null; then
    break
  fi
  sleep 1
done

uv sync --project "$root" --quiet
cd "$root"
TES_AUTHZ_KUBERNETES_URL="http://127.0.0.1:$port/access/v1/evaluation" \
  uv run --project "$root" pytest -p no:cacheprovider -m kubernetes "$@"

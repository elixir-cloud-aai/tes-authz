"""The Kubernetes manifest of the decision service (`deploy/kubernetes/`).

The static checks run with the unit tests. The replay of the golden
requests needs the service deployed by `scripts/test-kubernetes.sh`, which
sets `TES_AUTHZ_KUBERNETES_URL` (marker `kubernetes`).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from harness.golden import GoldenCase, load_cases

from .conftest import http

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "deploy" / "kubernetes" / "tes-authz.yaml"
SCRIPT = ROOT / "scripts" / "test-kubernetes.sh"
#: Files each ConfigMap of the manifest must be made from (`--from-file`).
CONFIGMAP_SOURCES = {
    "tes-authz-policy": ["engines/opa/policy/tes_authz.rego"],
    "tes-authz-shims": ["shims/common.py", "shims/opa_front.py"],
    "tes-authz-data": ["config/reference-policy.json"],
}
LABELS = {"app.kubernetes.io/name": "tes-authz", "app.kubernetes.io/component": "decision-service"}


def _documents() -> dict[str, dict[str, Any]]:
    """Return the manifest's objects by kind."""
    documents = [d for d in yaml.safe_load_all(MANIFEST.read_text()) if d]
    by_kind = {d["kind"]: d for d in documents}
    assert len(by_kind) == len(documents), "one object per kind"
    return by_kind


def _containers() -> dict[str, dict[str, Any]]:
    """Return the Deployment's containers by name."""
    spec = _documents()["Deployment"]["spec"]["template"]["spec"]
    return {c["name"]: c for c in spec["containers"]}


def _compose_images() -> dict[str, str]:
    """Return the images of the compose services by service name."""
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    return {name: service["image"] for name, service in compose["services"].items() if "image" in service}


def test_manifest_has_deployment_service_and_network_policy():
    """The manifest holds exactly a Deployment, a Service and a NetworkPolicy."""
    assert set(_documents()) == {"Deployment", "Service", "NetworkPolicy"}


def test_images_are_pinned_by_digest_and_match_compose():
    """Both images are pinned by digest, with the tags CI tests in compose."""
    compose = _compose_images()
    expected = {"opa": compose["opa"], "opa-front": compose["opa-front"]}
    for name, container in _containers().items():
        match = re.fullmatch(r"docker\.io/(?:library/)?(?P<tag>[^@]+)@sha256:[0-9a-f]{64}", container["image"])
        assert match, f"{name}: not pinned by digest: {container['image']}"
        assert match["tag"] == expected[name], (
            f"{name}: bump the manifest to {expected[name]} (compose.yaml) and its index digest "
            f"(`docker buildx imagetools inspect {expected[name]}`, first `Digest:`)"
        )


def test_opa_listens_on_loopback_only():
    """OPA's Data API (unauthenticated) is bound to the pod's loopback."""
    opa = _containers()["opa"]
    assert "--addr=127.0.0.1:8181" in opa["args"]
    assert "--ignore=.*" in opa["args"], "ConfigMap volumes would load the policy twice"
    assert {p["containerPort"] for p in opa["ports"]} == {8282}
    front = _containers()["opa-front"]
    assert {e["name"]: e["value"] for e in front["env"]}["OPA_URL"] == "http://127.0.0.1:8181"


def test_service_exposes_only_the_front():
    """The ClusterIP Service serves only the front's port."""
    service = _documents()["Service"]["spec"]
    assert service["type"] == "ClusterIP"
    assert service["selector"] == LABELS
    assert [(p["port"], p["targetPort"]) for p in service["ports"]] == [(8080, "http")]
    front_ports = {p["name"]: p["containerPort"] for p in _containers()["opa-front"]["ports"]}
    assert front_ports == {"http": 8080}


def test_network_policy_admits_only_labelled_clients():
    """Only pods labelled `tes-authz/client: "true"` reach the front."""
    policy = _documents()["NetworkPolicy"]["spec"]
    assert policy["podSelector"]["matchLabels"] == LABELS
    assert policy["policyTypes"] == ["Ingress"]
    assert policy["ingress"] == [
        {
            "from": [{"podSelector": {"matchLabels": {"tes-authz/client": "true"}}}],
            "ports": [{"port": "http", "protocol": "TCP"}],
        }
    ]


def test_pod_is_hardened():
    """No service account token, non-root, read-only, no capabilities."""
    deployment = _documents()["Deployment"]
    assert deployment["spec"]["selector"]["matchLabels"] == LABELS
    spec = deployment["spec"]["template"]["spec"]
    assert spec["automountServiceAccountToken"] is False
    assert spec["enableServiceLinks"] is False
    # The fields that docs/operators.md tells OpenShift users to remove
    assert spec["securityContext"] == {
        "runAsNonRoot": True,
        "runAsUser": 65534,
        "runAsGroup": 65534,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    for name, container in _containers().items():
        context = container["securityContext"]
        assert context["allowPrivilegeEscalation"] is False, name
        assert context["readOnlyRootFilesystem"] is True, name
        assert context["capabilities"] == {"drop": ["ALL"]}, name
        assert all(mount.get("readOnly") for mount in container["volumeMounts"]), name
        assert set(container["resources"]) == {"requests", "limits"}, name
        for probe in ("readinessProbe", "livenessProbe"):
            assert container[probe]["httpGet"]["path"] == "/health", f"{name}: {probe}"


def test_configmaps_are_documented_and_made_from_existing_files():
    """Every ConfigMap volume is created by the test script from existing files."""
    spec = _documents()["Deployment"]["spec"]["template"]["spec"]
    names = {v["configMap"]["name"] for v in spec["volumes"]}
    assert names == set(CONFIGMAP_SOURCES)
    script = SCRIPT.read_text()
    docs = (ROOT / "docs" / "operators.md").read_text()
    for name, sources in CONFIGMAP_SOURCES.items():
        assert f"create configmap {name}" in script, name
        assert f"create configmap {name}" in docs, name
        for source in sources:
            assert (ROOT / source).is_file(), source
            assert source in script, source
            if name != "tes-authz-data":  # the docs use the operator's copy
                assert f"tes-authz/{source}" in docs, source


@pytest.fixture(scope="module")
def kubernetes_url() -> str:
    """The evaluation URL of the deployed service, or skip."""
    url = os.environ.get("TES_AUTHZ_KUBERNETES_URL")
    if not url:
        pytest.skip("TES_AUTHZ_KUBERNETES_URL not set (run scripts/test-kubernetes.sh)")
    return url


CASES = [c for c in load_cases() if "reference_policy" in c.expect]


@pytest.mark.kubernetes
@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_deployed_service_gives_golden_decisions(kubernetes_url: str, case: GoldenCase):
    """The deployed service answers every golden request as expected."""
    status, body = http("POST", kubernetes_url, case.request, {"X-Request-ID": f"k8s-{case.name}"})
    assert status == 200, f"answered {status}: {body}"
    assert isinstance(body, dict) and body.get("decision") is case.expect["reference_policy"], case.description

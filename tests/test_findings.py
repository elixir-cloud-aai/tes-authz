"""Checks of spec claims marked unverified or taken from documentation.

Each test pins one observed behaviour of the pinned engine versions; the
README's findings section reports the results.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

import opa_front
from common import UpstreamError
from harness.engines import ENGINES, OPENFGA_API

from .conftest import http

pytestmark = pytest.mark.services

# A member entitlement. Owners no longer need one (Q11, option a); it keeps the
# requests realistic and the entitlement list in the condition context.
MEMBER = "urn:geant:lifescience-ri.eu:group:example-vo#login.aai.lifescience-ri.eu"


@pytest.fixture(scope="module")
def fga_eval(services) -> str:
    """OpenFGA's own AuthZEN endpoint for the reference store (bypassing the shim)."""
    status, body = http("GET", f"{OPENFGA_API}/stores")
    assert status == 200
    stores = [s for s in body["stores"] if s["name"] == "tes-authz-reference"]
    assert stores, "setup job did not create the store"
    return f"{OPENFGA_API}/stores/{stores[-1]['id']}/access/v1/evaluation"


def _owner_req(subject_props, resource_props, subject_id="u1"):
    return {
        "subject": {"type": "user", "id": subject_id, "properties": subject_props},
        "action": {"name": "GetTask"},
        "resource": {"type": "tes_service", "id": "tes-authz-test", "properties": resource_props},
    }


def test_openfga_missing_condition_parameter_is_an_error(fga_eval):
    """Spec section 7 / review 2 finding 3: missing parameter -> error, not deny."""
    status, body = http("POST", fga_eval, _owner_req({"id": "u1", "entitlements": [MEMBER]}, {}))
    assert status == 400
    assert "missing context parameters" in body["message"] and "resource_owner" in body["message"]


def test_openfga_subject_id_is_not_in_condition_context(fga_eval):
    """Spec section 7: only subject properties reach the context, not subject.id."""
    status, body = http("POST", fga_eval, _owner_req({"entitlements": [MEMBER]}, {"owner": "u1"}))
    assert status == 400
    assert "subject_id" in body["message"]


def test_openfga_with_all_parameters_decides(fga_eval):
    """With all parameters present, OpenFGA decides instead of failing."""
    status, body = http("POST", fga_eval, _owner_req({"id": "u1", "entitlements": [MEMBER]}, {"owner": "u1"}))
    assert (status, body) == (200, {"decision": True})
    status, body = http("POST", fga_eval, _owner_req({"id": "u1", "entitlements": [MEMBER]}, {"owner": ""}))
    assert (status, body) == (200, {"decision": False})


@pytest.mark.parametrize(
    ("subject_id", "resource_id", "field"),
    [
        ("https://iss.example.org/|sub", "tes-authz-test", "Subject.Id"),
        ("a@b", "tes-authz-test", "Subject.Id"),
        ("a b", "tes-authz-test", "Subject.Id"),
        ("x" * 501, "tes-authz-test", "Subject.Id"),
        ("u1", "y" * 257, "Resource.Id"),
        ("u1", "task:1", "Resource.Id"),
    ],
)
def test_openfga_identifier_limits(fga_eval, subject_id, resource_id, field):
    """Spec section 7 [unverified] ID pattern/length limits: confirmed."""
    req = _owner_req({"id": subject_id, "entitlements": []}, {"owner": ""}, subject_id)
    req["resource"]["id"] = resource_id
    status, body = http("POST", fga_eval, req)
    assert status == 400 and f"invalid {field}" in body["message"]


def test_openfga_identifier_limit_boundaries(fga_eval):
    """500-character subjects and 256-character objects are accepted."""
    req = _owner_req({"id": "u", "entitlements": []}, {"owner": ""}, "x" * 500)
    req["resource"]["id"] = "y" * 256
    assert http("POST", fga_eval, req)[0] == 200


def test_openfga_unknown_relation_is_an_error(fga_eval):
    """An action that is not a relation errors (so the shim validates actions first)."""
    req = _owner_req({"id": "u1", "entitlements": [MEMBER]}, {"owner": ""})
    req["action"]["name"] = "DeleteTask"
    status, body = http("POST", fga_eval, req)
    assert status == 400 and "not found" in body["message"]


def test_openfga_answers_decision_only(fga_eval):
    """Spec section 3.5: native AuthZEN PDPs return only ``decision``."""
    status, body = http("POST", fga_eval, _owner_req({"id": "u1", "entitlements": [MEMBER]}, {"owner": "u1"}))
    assert status == 200 and set(body) == {"decision"}


def test_openfga_does_not_echo_request_id(fga_eval):
    """OpenFGA does not echo a client-supplied X-Request-ID."""
    req = urllib.request.Request(
        fga_eval,
        method="POST",
        data=b'{"subject":{"type":"user","id":"u"},'
        b'"action":{"name":"GetTask"},"resource":{"type":"tes_service","id":"x",'
        b'"properties":{"owner":""}},"context":{}}',
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Request-ID", "tes-authz-findings-1")
    with urllib.request.urlopen(req, timeout=5) as response:
        assert response.headers.get("X-Request-ID") != "tes-authz-findings-1"


def test_shims_echo_request_id(services):
    """The shims echo X-Request-ID for log correlation."""
    for engine in ENGINES.values():
        req = urllib.request.Request(engine.host_url, method="POST", data=b"{}")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Request-ID", "tes-authz-findings-2")
        with urllib.request.urlopen(req, timeout=5) as response:
            assert response.headers.get("X-Request-ID") == "tes-authz-findings-2"


def test_opa_front_fails_closed_when_opa_is_down(monkeypatch):
    """The OPA front raises (502 to the TES) when OPA is unreachable."""
    monkeypatch.setattr(opa_front, "OPA_URL", "http://127.0.0.1:9")
    with pytest.raises(UpstreamError):
        opa_front.decide({"input": "x"}, {})


def _get_request(subject_id: str, owner: str, service_id: str = "tes-authz-test") -> dict:
    return {
        "subject": {"type": "user", "id": subject_id},
        "action": {"name": "GetTask"},
        "resource": {"type": "tes_task", "id": "t1", "properties": {"owner": owner}},
        "context": {"tes": {"profile": "tes-authzen/1", "service_id": service_id}},
    }


def test_shims_deny_lone_surrogates(services):
    """Lone surrogates would compare equal in OPA (U+FFFD); both shims deny them."""
    body = json.dumps(_get_request("\ud800", "\udbff")).encode()
    for engine in ENGINES.values():
        req = urllib.request.Request(engine.host_url, method="POST", data=body)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=5) as response:
            assert json.loads(response.read()) == {"decision": False}, engine.name


def test_shims_deny_service_id_with_newline(services):
    """A trailing newline must not slip through identifier encoding."""
    for engine in ENGINES.values():
        expected = (200, {"decision": False})
        assert http("POST", engine.host_url, _get_request("u1", "u1", "tes-authz-test\n")) == expected, engine.name


def test_shims_require_content_length(services):
    """Chunked or length-less requests get 411, not a silent deny."""
    for engine in ENGINES.values():
        req = urllib.request.Request(engine.host_url, method="POST", data=iter([b"{}"]))
        req.add_header("Content-Type", "application/json")
        req.add_header("Transfer-Encoding", "chunked")
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as exc:
            assert exc.code == 411, engine.name
        else:
            raise AssertionError(f"{engine.name} accepted a chunked request")


def test_openfga_shim_rejects_lists_over_limit(services):
    """Above SHIM_MAX_LIST_ITEMS the OpenFGA shim fails the request (502) instead of guessing."""
    req = _get_request("u1", "u1")
    req["subject"]["properties"] = {"claims": {"eduperson_entitlement": [*(f"urn:x:{i}" for i in range(1024)), MEMBER]}}
    assert http("POST", ENGINES["openfga"].host_url, req)[0] == 502
    assert http("POST", ENGINES["opa"].host_url, req) == (200, {"decision": True})


def test_shims_publish_authzen_metadata(services):
    """The shims serve AuthZEN metadata with their evaluation URL."""
    for engine in ENGINES.values():
        base = engine.host_url.removesuffix("/access/v1/evaluation")
        status, body = http("GET", base + "/.well-known/authzen-configuration")
        assert status == 200 and body["access_evaluation_endpoint"] == engine.host_url


def test_openfga_missing_parameter_without_membership_never_allows(fga_eval):
    """A request without ``resource_owner`` gets 400 or a deny from OpenFGA, never an allow."""
    status, body = http("POST", fga_eval, _owner_req({"id": "u1", "entitlements": []}, {}))
    assert status == 400 or (status, body) == (200, {"decision": False})

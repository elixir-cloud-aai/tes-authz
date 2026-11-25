"""Unit tests of the generic shim steps and the OpenFGA request mapping."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import common
import openfga_shim
from harness.golden import load_cases

from .service_clients import MALFORMED_SERVICE_CLIENTS

ROOT = Path(__file__).resolve().parent.parent
NO_CLIENT = {"iss": "", "sub": "", "client_id": ""}
"""The shim's ``iss``, ``sub`` and ``client_id`` parameters when the subject has none."""
URL_CASES = json.loads((ROOT / "golden" / "url-stripping.json").read_text())
POLICY = json.loads((ROOT / "config" / "reference-policy.json").read_text())


@pytest.mark.parametrize("case", URL_CASES, ids=[c["input"] for c in URL_CASES])
def test_strip_url(case):
    """The URL stripping rule gives the golden result for each case."""
    assert common.strip_url(case["input"]) == case["expected"]


def test_expand_prefixes():
    """Prefix expansion adds the delimiter-terminated prefixes."""
    assert common.expand_prefixes(["a:b:c#x"]) == ["a:", "a:b:", "a:b:c#x"]
    assert common.expand_prefixes(["/vo/sub"], delimiters="/") == ["/", "/vo/", "/vo/sub"]
    assert common.expand_prefixes([]) == []


def _startswith_member(values, prefixes, entitlements):
    return any(e in values or any(e.startswith(p) for p in prefixes) for e in entitlements)


def _expanded_member(values, prefixes, entitlements, delimiters=":"):
    expanded = set(common.expand_prefixes(entitlements, delimiters))
    return bool(expanded & (set(values) | set(prefixes)))


def _golden_entitlement_sets():
    sets = []
    for case in load_cases():
        claims = case.request.get("subject", {}).get("properties", {}).get("claims", {})
        if isinstance(claims, dict):
            sets.append(common.string_list(claims.get(POLICY["entitlement_claim"])))
    return sets


def test_prefix_expansion_matches_startswith_for_delimited_prefixes():
    """Spec claim: expansion equals startswith when prefixes end in a delimiter."""
    values, prefixes = POLICY["members"]["values"], POLICY["members"]["prefixes"]
    assert all(p.endswith(":") for p in prefixes)
    for ents in _golden_entitlement_sets():
        assert _startswith_member(values, prefixes, ents) == _expanded_member(values, prefixes, ents)


def test_reference_policy_has_no_admins():
    """Owner only (spec section 7): the reference policy data has no admin group."""
    assert "admins" not in POLICY


@pytest.fixture(scope="module")
def openfga_setup() -> ModuleType:
    """Load ``engines/openfga/setup.py`` once (it is a script, not a package module).

    Returns:
        The loaded module.
    """
    spec = importlib.util.spec_from_file_location("openfga_setup", ROOT / "engines" / "openfga" / "setup.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_openfga_setup_refuses_admins(openfga_setup):
    """The OpenFGA setup job refuses policy data that still has ``admins`` (upgrade notes)."""
    setup = openfga_setup
    setup.check_policy(POLICY)
    with pytest.raises(SystemExit, match="has 'admins'"):
        setup.check_policy({**POLICY, "admins": {"values": ["urn:a"], "prefixes": []}})


def test_openfga_setup_tuples_are_owner_only(openfga_setup):
    """No admin tuples and no tuples on ``all``; the ``own`` lister is unconditioned."""
    tuples = openfga_setup.tuples_for(POLICY)
    assert not any(t["object"].endswith("/all") for t in tuples)
    assert {t["relation"] for t in tuples} == {"creator", "service_client", "image_ok", "lister", "owner"}
    assert all("condition" not in t for t in tuples if t["relation"] == "lister")


def test_openfga_setup_service_client_tuple(openfga_setup):
    """Listed service clients become one ``listed_client`` tuple per service, pairs joined by one space."""
    clients = [t for t in openfga_setup.tuples_for(POLICY) if t["relation"] == "service_client"]
    assert len(clients) == len(POLICY["services"])
    expected = [f"{c['iss']} {c['client_id']}" for c in POLICY["service_clients"]]
    assert all(t["condition"] == {"name": "listed_client", "context": {"allowed_clients": expected}} for t in clients)
    without = {k: v for k, v in POLICY.items() if k != "service_clients"}
    empty = [t for t in openfga_setup.tuples_for(without) if t["relation"] == "service_client"]
    assert all(t["condition"]["context"] == {"allowed_clients": []} for t in empty)
    openfga_setup.check_policy(without)
    openfga_setup.check_policy({**POLICY, "service_clients": []})


def test_openfga_self_check_walks_the_service_clients(openfga_setup):
    """The self-check subject is an unlisted client, so ``listed_client`` compares against every pair."""
    service = POLICY["services"][0]
    cases = openfga_setup.worst_cases(POLICY, service)
    assert [c["action"]["name"] for c in cases] == ["ListTasks", "CreateTask", "CreateTask"]
    member = (POLICY["members"]["values"] + POLICY["members"]["prefixes"])[-1]
    non_member = cases[-1]["subject"]["properties"]["claims"][POLICY["entitlement_claim"]]
    assert member not in non_member and len(non_member) == openfga_setup.MAX_LIST_ITEMS
    for case in cases:
        props = case["subject"]["properties"]
        assert props["sub"] == props["client_id"]
        assert {"iss": props["iss"], "client_id": props["client_id"]} not in POLICY["service_clients"]
        mapped = openfga_shim.to_openfga(case, {"entitlements": POLICY["entitlement_claim"]})
        assert mapped["subject"]["properties"]["client_id"] == props["client_id"]


def test_openfga_self_check_client_is_never_listed(openfga_setup):
    """The self-check client stays unlisted even when the data lists the obvious candidates."""
    listed = [{"iss": "self-check", "client_id": f"self-check-{i}"} for i in range(3)]
    case = openfga_setup.worst_cases({**POLICY, "service_clients": listed}, POLICY["services"][0])[-1]
    props = case["subject"]["properties"]
    assert {"iss": props["iss"], "client_id": props["client_id"]} not in listed


@pytest.mark.parametrize("clients", MALFORMED_SERVICE_CLIENTS.values(), ids=MALFORMED_SERVICE_CLIENTS.keys())
def test_openfga_setup_refuses_malformed_service_clients(openfga_setup, clients):
    """Malformed ``service_clients`` stop the setup job (OPA denies every request for the same data)."""
    with pytest.raises(SystemExit, match="malformed 'service_clients'"):
        openfga_setup.check_policy({**POLICY, "service_clients": clients})


def test_prefix_expansion_differs_for_undelimited_prefix():
    """Spec claim: a prefix without a trailing delimiter decides differently."""
    ents = ["urn:g:vo2#x"]
    assert _startswith_member([], ["urn:g:vo"], ents) is True
    assert _expanded_member([], ["urn:g:vo"], ents) is False


def test_string_list():
    """Claim values normalise to lists of strings."""
    assert common.string_list("a") == ["a"]
    assert common.string_list(["a", 1, None, "b"]) == ["a", "b"]
    assert common.string_list(None) == []
    assert common.string_list({"a": 1}) == []


def test_encode_id():
    """Unsafe identifiers become fixed-length hashes; safe ones stay."""
    assert common.encode_id("tes-authz-test") == "tes-authz-test"
    for odd in ("https://iss|sub", "x" * 300, "h-abc", "a b", ""):
        encoded = common.encode_id(odd)
        assert encoded.startswith("h-") and len(encoded) == 66


def _valid():
    return {
        "subject": {"type": "user", "id": "u"},
        "action": {"name": "GetTask"},
        "resource": {"type": "tes_task", "id": "t"},
        "context": {"tes": {"profile": "tes-authzen/1", "service_id": "s"}},
    }


def test_validate_accepts_profile_request():
    """A minimal profile request passes validation."""
    common.validate_request(_valid())


@pytest.mark.parametrize("profile", ["tes-authzen/1", "tes-authzen/2", "tes-authzen/3"])
def test_validate_accepts_every_profile(profile):
    """Requests in profile /1, /2 and /3 pass validation."""
    req = _valid()
    req["context"]["tes"]["profile"] = profile
    common.validate_request(req)


def test_validate_accepts_profile_2_subject_properties():
    """The /2 subject and task properties are accepted (spec section 12)."""
    req = _valid()
    req["context"]["tes"]["profile"] = "tes-authzen/2"
    req["subject"]["properties"] = {
        "via": "apikey",
        "credential_id": "key-1",
        "key_age": 60,
        "snapshot_age": 60,
        "actor": {"iss": "https://iss", "sub": "proxy"},
    }
    req["resource"]["properties"] = {"owner": "u", "groups": ["lab-alpha"]}
    common.validate_request(req)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("subject", "type"), "client"),
        (("subject", "id"), ""),
        (("action", "name"), "DeleteTask"),
        (("resource", "type"), "tes_service"),
        (("resource", "id"), ""),
        (("resource", "properties"), "x"),
        (("context", "tes"), {"profile": "tes-authzen/4", "service_id": "s"}),
        (("context", "tes"), {"profile": "tes-authzen", "service_id": "s"}),
        (("context", "tes"), {"profile": ["tes-authzen/1"], "service_id": "s"}),
        (("context", "tes"), {"profile": "tes-authzen/1"}),
    ],
)
def test_validate_rejects(path, value):
    """Each contract violation is rejected."""
    req = _valid()
    req[path[0]][path[1]] = value
    with pytest.raises(common.ContractError):
        common.validate_request(req)


@pytest.mark.parametrize("action", ["RevokeApiKeys", "ListApiKeys", "GetTask", "ListTasks"])
def test_validate_rejects_poiesis_api_keys(action):
    """The Poiesis-only resource type poiesis_api_keys is not part of the profile."""
    req = _valid()
    req["context"]["tes"]["profile"] = "tes-authzen/2"
    req["action"] = {"name": action, "properties": {}}
    req["resource"] = {"type": "poiesis_api_keys", "id": "u"}
    with pytest.raises(common.ContractError):
        common.validate_request(req)


def test_validate_rejects_unknown_set():
    """Task set IDs other than own/all are rejected."""
    req = _valid()
    req["resource"] = {"type": "tes_task_set", "id": "group:x"}
    with pytest.raises(common.ContractError):
        common.validate_request(req)


@pytest.mark.parametrize("profile", ["tes-authzen/1", "tes-authzen/2"])
def test_validate_accepts_all_set_before_profile_3(profile):
    """Under /1 and /2, 'all' is in the vocabulary (the reference policy denies it)."""
    req = _valid()
    req["context"]["tes"]["profile"] = profile
    req["action"] = {"name": "ListTasks", "properties": {"view": "MINIMAL"}}
    req["resource"] = {"type": "tes_task_set", "id": "all"}
    common.validate_request(req)


@pytest.mark.parametrize("action", ["ListTasks", "CreateTask"])
def test_validate_rejects_all_set_in_profile_3(action):
    """Profile /3 removes tes_task_set:all from the vocabulary (spec section 13)."""
    req = _valid()
    req["context"]["tes"]["profile"] = "tes-authzen/3"
    req["action"] = {"name": action, "properties": {}}
    req["resource"] = {"type": "tes_task_set", "id": "all"}
    with pytest.raises(common.ContractError, match="unknown task set"):
        common.validate_request(req)


def test_openfga_mapping_always_passes_condition_parameters():
    """Review 2, finding 3: owner and subject ID are never missing."""
    req = _valid()
    out = openfga_shim.to_openfga(req, {"entitlements": "eduperson_entitlement"})
    assert out["subject"]["properties"] == {"id": "u", **NO_CLIENT, "entitlements": []}
    # No task projection: one empty image, which no allowlist prefix matches.
    assert out["resource"] == {"type": "tes_service", "id": "s", "properties": {"owner": "", "images": [""]}}
    assert out["subject"]["id"].startswith("h-")
    assert "context" not in out


def test_openfga_mapping_ignores_profile_2_properties():
    """The /2 subject and task properties never reach OpenFGA."""
    claims = {"eduperson_entitlement": ["urn:a"]}
    plain = _valid()
    plain["subject"]["properties"] = {"claims": claims}
    plain["resource"]["properties"] = {"owner": "u"}
    extended = _valid()
    extended["context"]["tes"]["profile"] = "tes-authzen/2"
    extended["subject"]["properties"] = {
        "claims": claims,
        "via": "apikey",
        "credential_id": "key-1",
        "key_age": 60,
        "snapshot_age": 60,
        "actor": {"iss": "https://iss", "sub": "proxy"},
    }
    extended["resource"]["properties"] = {"owner": "u", "groups": ["lab-alpha"]}
    claim_map = {"entitlements": "eduperson_entitlement"}
    out = openfga_shim.to_openfga(extended, claim_map)
    plain_out = openfga_shim.to_openfga(plain, claim_map)
    assert out["subject"]["properties"] == plain_out["subject"]["properties"]
    assert out["subject"]["properties"] == {"id": "u", **NO_CLIENT, "entitlements": ["urn:a"]}
    assert out["resource"] == plain_out["resource"]
    assert out["action"] == plain_out["action"]


def test_openfga_mapping_ignores_actor():
    """The shim ignores ``actor``: a delegated token maps like its subject (no ``delegated`` parameter)."""
    req = _valid()
    req["subject"]["properties"] = {"actor": {"iss": "https://iss", "sub": "proxy"}}
    assert openfga_shim.to_openfga(req, {})["subject"]["properties"] == {"id": "u", **NO_CLIENT}


def test_openfga_mapping_passes_service_client_identity():
    """``iss``, ``sub`` and ``client_id`` reach the ``listed_client`` condition; other types become ``""``."""
    req = _valid()
    req["subject"]["properties"] = {"iss": "https://iss", "sub": "c1", "client_id": "c1", "scope": ["openid"]}
    props = openfga_shim.to_openfga(req, {})["subject"]["properties"]
    assert props == {"id": "u", "iss": "https://iss", "sub": "c1", "client_id": "c1"}
    req["subject"]["properties"] = {"iss": ["https://iss"], "sub": 1, "client_id": None}
    assert openfga_shim.to_openfga(req, {})["subject"]["properties"] == {"id": "u", **NO_CLIENT}


def test_openfga_mapping_task_set_and_claims():
    """Task sets are service-scoped; images and claims are flattened."""
    req = _valid()
    req["subject"]["properties"] = {"claims": {"eduperson_entitlement": "urn:a"}}
    req["action"]["name"] = "CreateTask"
    req["resource"] = {
        "type": "tes_task_set",
        "id": "own",
        "properties": {"task": {"executors": [{"image": "i"}, {"x": 1}]}},
    }
    out = openfga_shim.to_openfga(req, {"entitlements": "eduperson_entitlement"})
    assert out["resource"]["id"] == "s/own"
    assert out["resource"]["properties"]["images"] == ["i", ""]
    assert out["subject"]["properties"]["entitlements"] == ["urn:a"]


def test_parse_claim_map():
    """FGA_CLAIMS parses into parameter-to-claim pairs."""
    assert openfga_shim.parse_claim_map("a=x, b=https://e.org/g") == {"a": "x", "b": "https://e.org/g"}
    with pytest.raises(ValueError):
        openfga_shim.parse_claim_map("bad")


def test_parse_claim_map_rejects_reserved_parameters():
    """Claims can't overwrite the shim's own subject parameters (``id``, ``iss``, ``sub``, ``client_id``)."""
    for param in ("id", "iss", "sub", "client_id"):
        with pytest.raises(ValueError):
            openfga_shim.parse_claim_map(f"{param}=x")
    assert openfga_shim.parse_claim_map("delegated=x") == {"delegated": "x"}


def _create(profile: str, owner: object = None) -> dict[str, Any]:
    req = _valid()
    req["context"]["tes"]["profile"] = profile
    req["action"] = {"name": "CreateTask", "properties": {}}
    props: dict[str, Any] = {"task": {"executors": [{"image": "docker.io/library/alpine"}]}}
    if owner is not None:
        props["owner"] = owner
    req["resource"] = {"type": "tes_task_set", "id": "own", "properties": props}
    return req


def test_validate_accepts_owner_on_create_in_profile_3() -> None:
    """Profile /3: CreateTask names the caller as owner (spec section 13)."""
    common.validate_request(_create("tes-authzen/3", owner="u"))


@pytest.mark.parametrize("owner", [None, "someone-else", "", 42])
def test_validate_rejects_create_without_the_caller_as_owner_in_profile_3(owner: object) -> None:
    """Profile /3: a CreateTask without the caller as owner is a contract error."""
    with pytest.raises(common.ContractError, match="owner"):
        common.validate_request(_create("tes-authzen/3", owner=owner))


@pytest.mark.parametrize("profile", ["tes-authzen/1", "tes-authzen/2"])
def test_validate_accepts_create_without_owner_before_profile_3(profile: str) -> None:
    """Profiles /1 and /2 have no owner on CreateTask."""
    common.validate_request(_create(profile))

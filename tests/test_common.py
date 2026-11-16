"""Unit tests of the generic shim steps and the OpenFGA request mapping."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import common
import openfga_shim
from harness.golden import load_cases

ROOT = Path(__file__).resolve().parent.parent
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
    for group in ("members", "admins"):
        values, prefixes = POLICY[group]["values"], POLICY[group]["prefixes"]
        assert all(p.endswith(":") for p in prefixes)
        for ents in _golden_entitlement_sets():
            assert _startswith_member(values, prefixes, ents) == _expanded_member(values, prefixes, ents)


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


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("subject", "type"), "client"),
        (("subject", "id"), ""),
        (("action", "name"), "DeleteTask"),
        (("resource", "type"), "tes_service"),
        (("resource", "id"), ""),
        (("resource", "properties"), "x"),
        (("context", "tes"), {"profile": "tes-authzen/2", "service_id": "s"}),
        (("context", "tes"), {"profile": "tes-authzen/1"}),
    ],
)
def test_validate_rejects(path, value):
    """Each contract violation is rejected."""
    req = _valid()
    req[path[0]][path[1]] = value
    with pytest.raises(common.ContractError):
        common.validate_request(req)


def test_validate_rejects_unknown_set():
    """Task set IDs other than own/all are rejected."""
    req = _valid()
    req["resource"] = {"type": "tes_task_set", "id": "group:x"}
    with pytest.raises(common.ContractError):
        common.validate_request(req)


def test_openfga_mapping_always_passes_condition_parameters():
    """Review 2, finding 3: owner and subject ID are never missing."""
    req = _valid()
    out = openfga_shim.to_openfga(req, {"entitlements": "eduperson_entitlement"})
    assert out["subject"]["properties"] == {"id": "u", "entitlements": []}
    # No task projection: one empty image, which no allowlist prefix matches.
    assert out["resource"] == {"type": "tes_service", "id": "s", "properties": {"owner": "", "images": [""]}}
    assert out["subject"]["id"].startswith("h-")
    assert "context" not in out


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

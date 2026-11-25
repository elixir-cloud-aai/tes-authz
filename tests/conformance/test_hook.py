"""Hook conformance (layer 1): each TES against the recording stub.

Case numbers refer to spec draft 3, section 8.2. The userinfo cases (6b,
20, 21) run for adapters with the ``userinfo`` feature, against the mock
OIDC issuer. Startup checks (23, 30) and gRPC (24) need features the mock
TES lacks or has only in process; the mock's startup checks are unit-tested
in ``tests/test_mock_settings.py``.

By default only ``CreateTask`` asks the decision service; ``ALL_OPERATIONS``
switches on the other three (``authz.operations``, spec section 3).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from harness.golden import diff, instantiate
from harness.stub_client import ALLOW, DENY, rule
from harness.tes import Identity, RequiredClaim

from .conftest import ALICE, BOB, CAROL, NEAR_MISS, SCOPE, SERVICE_CLIENT, SUBGROUP, VO, contains

pytestmark = pytest.mark.services

GOLDEN_CREATE = json.loads((Path(__file__).resolve().parents[2] / "golden" / "hook" / "create.json").read_text())
RULE = RequiredClaim("eduperson_entitlement", (), (VO + ":",))
ALLOWLIST = ("eduperson_entitlement",)
ALL_OPERATIONS = ("create", "get", "list", "cancel")
"""``authz.operations`` with every operation switched on."""
DOWN = {"close": True}
"""Stub response: drop the connection (decision service down)."""


def scope(value):
    """Return a stub response that allows with a list scope.

    Args:
        value: The ``context.tes.list_scope`` value.

    Returns:
        The response specification.
    """
    return {"status": 200, "body": {"decision": True, "context": {"tes": {"list_scope": value}}}}


def test_case_02_service_info_open(start, stub):
    """Case 2: service-info answers without a token."""
    tes = start()
    assert tes.call("GET", "/service-info", None)[0] == 200


def test_case_05_rule_fails_pdp_not_called(start, stub):
    """Case 5/16: a failing claim rule gives 403 on CreateTask without a PDP call; other actions aren't gated."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", required_claim=RULE, claims=ALLOWLIST)
    assert tes.create(CAROL)[0] == 403
    assert stub.requests() == []
    assert tes.call("GET", "/tasks", CAROL) == (200, {"tasks": []})
    assert tes.call("GET", "/tasks/x", CAROL)[0] == 404
    assert tes.call("POST", "/tasks/x:cancel", CAROL)[0] == 404


def test_case_05e_owner_keeps_tasks_without_the_claim(start, stub):
    """Case 5e: an owner who lost the claim still gets, lists and cancels their own tasks."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", required_claim=RULE, claims=ALLOWLIST)
    task_id = tes.create(ALICE)[1]["id"]
    revoked = Identity(ALICE.sub, {"scope": SCOPE})
    assert tes.create(revoked)[0] == 403
    assert tes.call("GET", f"/tasks/{task_id}", revoked)[0] == 200
    assert [t["id"] for t in tes.call("GET", "/tasks", revoked)[1]["tasks"]] == [task_id]
    assert tes.call("POST", f"/tasks/{task_id}:cancel", revoked)[0] == 200


def test_case_04b_near_miss_prefix(start):
    """Case 4b: a prefix without the delimiter boundary does not admit."""
    tes = start(required_claim=RULE)
    assert tes.create(CAROL)[0] == 403
    assert tes.create(ALICE)[0] == 200


def test_case_05b_rule_without_pdp_or_allowlist(start):
    """Case 5b: the rule works without PDP and allowlist."""
    tes = start(required_claim=RequiredClaim("eduperson_entitlement", (SUBGROUP,)))
    assert tes.create(ALICE)[0] == 200


@pytest.mark.parametrize("name", ["ctx.groups", "https://e.org/groups"])
def test_case_05c_dotted_path_and_uri_name(start, name):
    """Case 5c: the rule finds dotted paths and URI-named claims."""
    claims = {"ctx": {"groups": ["g1"]}} if name == "ctx.groups" else {"https://e.org/groups": ["g1"]}
    tes = start(required_claim=RequiredClaim(name, ("g1",)))
    assert tes.create(Identity("u", claims))[0] == 200
    assert tes.create(ALICE)[0] == 403


def test_case_05d_client_credentials_without_claim(start):
    """Case 5d: client-credentials tokens without the claim get 403."""
    tes = start(required_claim=RULE)
    assert tes.create(SERVICE_CLIENT)[0] == 403


def test_case_07_create_request_matches_golden(start, stub, adapter):
    """Case 7: the CreateTask request equals the golden file; no secrets."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", claims=ALLOWLIST)
    status, body = tes.call("POST", "/tasks", ALICE, GOLDEN_CREATE["submit"])
    assert status == 200
    (recorded,) = stub.requests()
    fixtures = {
        "subject_id": adapter.owner_id(ALICE),
        "sub": ALICE.sub,
        "scope": ALICE.claims["scope"].split(),
        **adapter.subject_fixtures(ALICE),
    }
    expected = instantiate(GOLDEN_CREATE["request"], fixtures)
    # A TES with a fixed service-info id (Funnel) reports it as a fixture.
    expected["context"]["tes"]["service_id"] = fixtures.get("service_id", expected["context"]["tes"]["service_id"])
    assert diff(expected, recorded["body"]) == []
    assert not contains(recorded, "do-not-send")
    assert recorded["headers"]["Authorization"] is None
    assert body["id"] != "client-chosen-id"


def test_case_07b_server_assigned_id_and_state(start, stub):
    """Case 7b: client-supplied ID and state are ignored."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub")
    status, body = tes.call("POST", "/tasks", ALICE, GOLDEN_CREATE["submit"])
    assert status == 200 and body["id"] != "client-chosen-id"
    status, task = tes.call("GET", f"/tasks/{body['id']}?view=FULL", ALICE)
    assert status == 200 and task["state"] != "COMPLETE"
    assert tes.call("GET", "/tasks/client-chosen-id", ALICE)[0] == 404


def test_case_08_pdp_denies_create(start, stub):
    """Case 8: a CreateTask deny gives 403 and stores nothing."""
    stub.script(default=DENY, rules=[rule(ALLOW, action="ListTasks", resource_id="own")])
    tes = start(decision_service="stub")
    assert tes.create(ALICE)[0] == 403
    assert tes.call("GET", "/tasks", ALICE)[1]["tasks"] == []


def test_case_09_foreign_task_404_even_if_pdp_allows(start, stub):
    """Case 9: another user's task is 404 for get and cancel, whatever the PDP says; the PDP isn't asked."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub")
    task_id = tes.create(BOB)[1]["id"]
    assert tes.call("GET", f"/tasks/{task_id}", BOB)[0] == 200
    stub.reset()
    stub.script(default=ALLOW)
    assert tes.call("GET", f"/tasks/{task_id}?view=FULL", ALICE)[0] == 404
    assert tes.call("POST", f"/tasks/{task_id}:cancel", ALICE)[0] == 404
    assert stub.requests() == []
    assert tes.call("GET", f"/tasks/{task_id}?view=BASIC", BOB)[1]["state"] == "QUEUED"


def test_case_10_pdp_denies_get_and_cancel(start, stub):
    """Case 10: switched on, a deny on the owner's get and cancel gives 404 and leaves the task unchanged."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", operations=ALL_OPERATIONS)
    task_id = tes.create(BOB)[1]["id"]
    stub.reset()
    stub.script(default=DENY)
    assert tes.call("GET", f"/tasks/{task_id}", BOB)[0] == 404
    assert tes.call("POST", f"/tasks/{task_id}:cancel", BOB)[0] == 404
    assert [r["body"]["action"]["name"] for r in stub.requests()] == ["GetTask", "CancelTask", "GetTask"]
    stub.script(default=ALLOW)
    assert tes.call("GET", f"/tasks/{task_id}?view=BASIC", BOB)[1]["state"] == "QUEUED"


def test_case_10b_get_allowed_cancel_denied(start, stub):
    """Case 10b: switched on, the owner's cancel denied but get allowed gives 403."""
    stub.script(default=ALLOW, rules=[rule(DENY, action="CancelTask")])
    tes = start(decision_service="stub", operations=ALL_OPERATIONS)
    task_id = tes.create(BOB)[1]["id"]
    assert tes.call("POST", f"/tasks/{task_id}:cancel", BOB)[0] == 403


def test_case_10b_cancel_only_switched_on(start, stub):
    """Case 10b: cancel switched on alone, a denied cancel is 403 for the owner (owner rule reads), else 404."""
    stub.script(default=ALLOW, rules=[rule(DENY, action="CancelTask")])
    tes = start(decision_service="stub", operations=("create", "cancel"))
    task_id = tes.create(BOB)[1]["id"]
    stub.reset()
    stub.script(default=ALLOW, rules=[rule(DENY, action="CancelTask")])
    assert tes.call("POST", f"/tasks/{task_id}:cancel", BOB)[0] == 403
    assert tes.call("POST", f"/tasks/{task_id}:cancel", ALICE)[0] == 404
    assert [r["body"]["action"]["name"] for r in stub.requests()] == ["CancelTask", "CancelTask"]


@pytest.mark.parametrize("decision", [ALLOW, DENY], ids=["allow", "deny"])
def test_case_11_missing_task(start, stub, decision):
    """Case 11: a missing task gives 404 on get and cancel; the PDP isn't asked."""
    stub.script(default=decision)
    tes = start(decision_service="stub")
    assert tes.call("GET", "/tasks/no-such-task", ALICE)[0] == 404
    assert tes.call("POST", "/tasks/no-such-task:cancel", ALICE)[0] == 404
    assert stub.requests() == []


def test_case_11c_cancel_parity(start, stub):
    """Case 11c: cancel on a missing and on a foreign task cost the same calls (none) and give 404."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub")
    task_id = tes.create(BOB)[1]["id"]
    stub.reset()
    stub.script(default=ALLOW)
    assert tes.call("POST", "/tasks/no-such-task:cancel", ALICE)[0] == 404
    assert tes.call("POST", f"/tasks/{task_id}:cancel", ALICE)[0] == 404
    assert stub.requests() == []


def test_case_11d_own_cancel_asks_cancel_then_get(start, stub):
    """Case 11d: switched on, a denied cancel of an own task asks CancelTask, then GetTask, with new request IDs."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", operations=ALL_OPERATIONS)
    task_id = tes.create(ALICE)[1]["id"]
    stub.reset()
    stub.script(default=DENY)
    assert tes.call("POST", f"/tasks/{task_id}:cancel", ALICE)[0] == 404
    recorded = stub.requests()
    assert [r["body"]["action"]["name"] for r in recorded] == ["CancelTask", "GetTask"]
    for r in recorded:
        assert r["body"]["resource"]["id"] == task_id
        assert set(r["body"]["resource"]["properties"]) == {"owner", "state", "tags"}
        assert r["body"]["action"]["properties"] == {}
    request_ids = [r["headers"]["X-Request-ID"] for r in recorded]
    assert None not in request_ids and len(set(request_ids)) == 2


def test_request_shape(start, stub, adapter):
    """Spec section 3.7: action properties always present, owner on create, no properties on list sets."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", operations=ALL_OPERATIONS)
    task_id = tes.create(ALICE)[1]["id"]
    tes.call("GET", f"/tasks/{task_id}?view=BASIC", ALICE)
    tes.call("GET", "/tasks?view=FULL", ALICE)
    tes.call("POST", f"/tasks/{task_id}:cancel", ALICE)
    recorded = stub.requests()
    by_action = {}
    for r in recorded:
        by_action.setdefault(r["body"]["action"]["name"], []).append(r["body"])
        subject = r["body"]["subject"]
        assert None not in subject["properties"].values()
        assert subject["properties"]["claims"] == {}
        assert r["body"]["context"]["tes"]["profile"] == GOLDEN_CREATE["request"]["context"]["tes"]["profile"]
    assert by_action["CreateTask"][0]["action"]["properties"] == {}
    assert by_action["CreateTask"][0]["resource"]["properties"]["owner"] == adapter.owner_id(ALICE)
    assert by_action["GetTask"][0]["action"]["properties"] == {"view": "BASIC"}
    assert set(by_action["GetTask"][0]["resource"]["properties"]) == {"owner", "state", "tags"}
    assert by_action["CancelTask"][0]["action"]["properties"] == {}
    assert [body["resource"] for body in by_action["ListTasks"]] == [{"type": "tes_task_set", "id": "own"}]
    assert by_action["ListTasks"][0]["action"]["properties"] == {"view": "FULL"}
    request_ids = [r["headers"]["X-Request-ID"] for r in recorded]
    assert len(set(request_ids)) == len(request_ids)


def test_case_11b_pdp_down(start, stub):
    """Case 11b: switched on and failing closed, an own, a missing and a foreign ID all give 503 (no oracle)."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", operations=ALL_OPERATIONS)
    task_id = tes.create(ALICE)[1]["id"]
    foreign_id = tes.create(BOB)[1]["id"]
    stub.script(default=DOWN)
    for path in (f"/tasks/{task_id}", "/tasks/no-such-task", f"/tasks/{foreign_id}"):
        assert tes.call("GET", path, ALICE)[0] == 503
        assert tes.call("POST", path + ":cancel", ALICE)[0] == 503
    assert tes.call("GET", "/tasks", ALICE)[0] == 503
    stub.script(default=ALLOW)
    assert tes.call("GET", f"/tasks/{task_id}?view=BASIC", ALICE)[1]["state"] == "QUEUED"


def test_case_25_default_reads_survive_a_pdp_outage(start, stub):
    """Case 25: by default only CreateTask asks; with the PDP down, create is 503, own tasks stay reachable."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub")
    task_id = tes.create(ALICE)[1]["id"]
    foreign_id = tes.create(BOB)[1]["id"]
    stub.reset()
    stub.script(default=DOWN)
    assert tes.create(ALICE)[0] == 503
    assert tes.call("GET", f"/tasks/{task_id}", ALICE)[0] == 200
    assert tes.call("GET", f"/tasks/{foreign_id}", ALICE)[0] == 404
    assert [t["id"] for t in tes.call("GET", "/tasks", ALICE)[1]["tasks"]] == [task_id]
    assert tes.call("POST", f"/tasks/{foreign_id}:cancel", ALICE)[0] == 404
    assert tes.call("POST", f"/tasks/{task_id}:cancel", ALICE)[0] == 200
    assert [r["body"]["action"]["name"] for r in stub.requests()] == ["CreateTask"]


def _pages(tes, who, size):
    ids, token = [], None
    for _ in range(50):
        status, page = tes.call("GET", f"/tasks?page_size={size}" + (f"&page_token={token}" if token else ""), who)
        assert status == 200
        assert len(page["tasks"]) <= size
        ids += [t["id"] for t in page["tasks"]]
        token = page.get("next_page_token")
        if not token:
            return ids
    raise AssertionError("paging did not end")


@pytest.mark.parametrize("operations", [("create",), ALL_OPERATIONS], ids=["default", "switched-on"])
def test_case_12_plain_allow_lists_own_tasks_only(start, stub, operations):
    """Case 12: a plain allow (or no call, by default) lists only the caller's own tasks; 'all' is never asked."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", operations=operations)
    created = {who.sub: [] for who in (ALICE, BOB)}
    for who in (ALICE, BOB, ALICE, BOB, ALICE):
        created[who.sub].append(tes.create(who)[1]["id"])
    stub.reset()
    stub.script(default=ALLOW)
    ids = _pages(tes, ALICE, 2)
    assert sorted(ids) == sorted(created[ALICE.sub]) and len(ids) == len(set(ids))
    asked = [(r["body"]["action"]["name"], r["body"]["resource"]["id"]) for r in stub.requests()]
    assert asked == ([("ListTasks", "own")] * 2 if "list" in operations else [])


def test_case_13_own_scope_lists_own_tasks(start, stub):
    """Case 13: the 'own' scope lists only own tasks across pages."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub")
    created = {who.sub: [] for who in (ALICE, BOB)}
    for who in (ALICE, BOB, ALICE, BOB, ALICE):
        created[who.sub].append(tes.create(who)[1]["id"])
    ids = _pages(tes, BOB, 1)
    assert sorted(ids) == sorted(created[BOB.sub]) and len(ids) == len(set(ids))


def test_case_14_list_denied_is_an_empty_list(start, stub):
    """Case 14: switched on, a ListTasks deny is the scope 'none': an empty list (200), after asking 'own' only."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", operations=ALL_OPERATIONS)
    tes.create(ALICE)
    stub.reset()
    stub.script(default=DENY)
    assert tes.call("GET", "/tasks", ALICE) == (200, {"tasks": []})
    assert [r["body"]["resource"]["id"] for r in stub.requests()] == ["own"]


def test_case_14_default_list_is_not_asked(start, stub):
    """Case 14: by default ListTasks isn't asked, so a PDP that denies everything still lists own tasks."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub")
    task_id = tes.create(ALICE)[1]["id"]
    stub.reset()
    stub.script(default=DENY)
    assert [t["id"] for t in tes.call("GET", "/tasks", ALICE)[1]["tasks"]] == [task_id]
    assert stub.requests() == []


def test_case_26_switched_on_operations_may_widen(start, stub):
    """Case 26: switched on, the decision service decides alone and may allow another owner's task."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", operations=ALL_OPERATIONS)
    task_id = tes.create(BOB)[1]["id"]
    stub.reset()
    stub.script(default=ALLOW)
    assert tes.call("GET", f"/tasks/{task_id}?view=BASIC", ALICE)[0] == 200
    assert tes.call("POST", f"/tasks/{task_id}:cancel", ALICE)[0] == 200
    (get, cancel) = stub.requests()
    assert get["body"]["resource"]["properties"]["owner"] == cancel["body"]["resource"]["properties"]["owner"]
    assert get["body"]["subject"]["id"] != get["body"]["resource"]["properties"]["owner"]
    assert tes.call("GET", f"/tasks/{task_id}?view=BASIC", BOB)[1]["state"] == "CANCELED"


def test_case_27_switched_on_asks_for_every_id(start, stub):
    """Case 27: switched on, own, foreign and missing IDs cost one call each; a missing one has empty properties."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", operations=ALL_OPERATIONS)
    own_id = tes.create(ALICE)[1]["id"]
    foreign_id = tes.create(BOB)[1]["id"]
    stub.reset()
    stub.script(default=DENY)
    for task_id in (own_id, foreign_id, "no-such-task"):
        assert tes.call("GET", f"/tasks/{task_id}", ALICE)[0] == 404
    stub.script(default=ALLOW)
    assert tes.call("GET", "/tasks/no-such-task", ALICE)[0] == 404
    assert tes.call("POST", "/tasks/no-such-task:cancel", ALICE)[0] == 404
    recorded = [r["body"]["resource"] for r in stub.requests()]
    assert [r["id"] for r in recorded] == [own_id, foreign_id, "no-such-task", "no-such-task", "no-such-task"]
    assert recorded[0]["properties"]["owner"] != recorded[1]["properties"]["owner"]
    assert [r["properties"] for r in recorded[2:]] == [{}, {}, {}]


@pytest.mark.parametrize(
    ("response", "expected"),
    [(ALLOW, "own"), (scope("own"), "own"), (scope("all"), "all"), (scope("none"), "none"), (DENY, "none")],
    ids=["plain-allow", "own", "all", "none", "deny"],
)
def test_case_28_list_scope(start, stub, response, expected):
    """Case 28: switched on, the list scope of the answer decides: own tasks, all tasks or an empty list."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", operations=ALL_OPERATIONS)
    created = {who.sub: [tes.create(who)[1]["id"], tes.create(who)[1]["id"]] for who in (ALICE, BOB)}
    stub.reset()
    stub.script(default=response)
    ids = _pages(tes, ALICE, 1)
    want = {"own": created[ALICE.sub], "all": created[ALICE.sub] + created[BOB.sub], "none": []}[expected]
    assert sorted(ids) == sorted(want) and len(ids) == len(set(ids))
    assert {r["body"]["resource"]["id"] for r in stub.requests()} == {"own"}


@pytest.mark.parametrize(
    "response",
    [scope("group:x"), scope(["all"]), {"status": 200, "body": {"decision": True, "context": "all"}}],
    ids=["unknown", "list", "context-not-object"],
)
def test_case_28_malformed_list_scope_is_503(start, stub, response):
    """Case 28: an unknown or malformed list scope is a failed decision: 503 when failing closed."""
    stub.script(default=response)
    tes = start(decision_service="stub", operations=ALL_OPERATIONS)
    assert tes.call("GET", "/tasks", ALICE)[0] == 503


def test_case_29_fail_open_falls_back_to_the_owner_rule(start, stub):
    """Case 29: with get, list and cancel failing open, a PDP outage gives the owner rule, never allow-all."""
    stub.script(default=ALLOW)
    failure = (("get", "open"), ("list", "open"), ("cancel", "open"))
    tes = start(decision_service="stub", operations=ALL_OPERATIONS, failure=failure)
    own_id = tes.create(ALICE)[1]["id"]
    foreign_id = tes.create(BOB)[1]["id"]
    stub.script(default=DOWN)
    assert tes.create(ALICE)[0] == 503
    assert tes.call("GET", f"/tasks/{own_id}", ALICE)[0] == 200
    assert tes.call("GET", f"/tasks/{foreign_id}", ALICE)[0] == 404
    assert tes.call("GET", "/tasks/no-such-task", ALICE)[0] == 404
    assert [t["id"] for t in tes.call("GET", "/tasks", ALICE)[1]["tasks"]] == [own_id]
    assert tes.call("POST", f"/tasks/{foreign_id}:cancel", ALICE)[0] == 404
    assert tes.call("POST", f"/tasks/{own_id}:cancel", ALICE)[0] == 200
    stub.script(default=ALLOW)
    assert tes.call("GET", f"/tasks/{foreign_id}?view=BASIC", BOB)[1]["state"] == "QUEUED"


def test_case_29_failure_mode_is_per_operation(start, stub):
    """Case 29: only the operations set to open fall back; the others stay closed (503)."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", operations=ALL_OPERATIONS, failure=(("list", "open"),))
    own_id = tes.create(ALICE)[1]["id"]
    stub.script(default=DOWN)
    assert [t["id"] for t in tes.call("GET", "/tasks", ALICE)[1]["tasks"]] == [own_id]
    assert tes.call("GET", f"/tasks/{own_id}", ALICE)[0] == 503
    assert tes.call("POST", f"/tasks/{own_id}:cancel", ALICE)[0] == 503


@pytest.mark.parametrize(
    "response",
    [
        {"delay": 2.5, "status": 200, "body": {"decision": True}},
        {"status": 500, "body": {"error": "x"}},
        {"status": 200, "body": {"decision": "true"}},
        {"status": 200, "body": {}},
        {"status": 200, "raw": "not json"},
    ],
    ids=["timeout", "500", "string-true", "no-decision", "not-json"],
)
def test_case_15_pdp_failure_is_503(start, stub, response):
    """Case 15: any PDP failure gives 503 and executes nothing."""
    stub.script(default=response, rules=[rule(ALLOW, action="ListTasks")])
    tes = start(decision_service="stub", timeout=1.0)
    assert tes.create(ALICE)[0] == 503
    assert tes.call("GET", "/tasks", ALICE)[1]["tasks"] == []


@pytest.mark.parametrize(
    ("method", "path", "action"),
    [("GET", "/tasks/{id}", "GetTask"), ("POST", "/tasks/{id}:cancel", "CancelTask"), ("GET", "/tasks", "ListTasks")],
)
def test_case_15_pdp_failure_on_every_action(start, stub, method, path, action):
    """Case 15: switched on, a PDP 500 gives 503 on get, cancel and list as well, and changes nothing."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", operations=ALL_OPERATIONS)
    task_id = tes.create(ALICE)[1]["id"]
    stub.script(default=ALLOW, rules=[rule({"status": 500, "body": {}}, action=action)])
    assert tes.call(method, path.format(id=task_id), ALICE)[0] == 503
    stub.script(default=ALLOW)
    assert tes.call("GET", f"/tasks/{task_id}?view=BASIC", ALICE)[1]["state"] == "QUEUED"


def test_case_17_rule_passes_pdp_denies(start, stub):
    """Case 17: claim rule AND PDP: a PDP deny wins over a passing rule."""
    stub.script(default=DENY)
    tes = start(decision_service="stub", required_claim=RULE)
    assert tes.create(ALICE)[0] == 403
    assert len(stub.requests()) == 1


def test_case_18_subject_from_token_only(start, stub, adapter):
    """Case 18: identity headers and client request IDs are ignored."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", claims=ALLOWLIST)
    headers = {"X-Request-ID": "client-request-id", "X-User": "bob-sub", "X-Forwarded-User": "bob-sub"}
    task = {
        "name": "t",
        "tags": {"owner": "bob-sub"},
        "executors": [{"image": "docker.io/library/alpine", "command": ["true"]}],
    }
    assert tes.call("POST", "/tasks", ALICE, task, headers)[0] == 200
    (recorded,) = stub.requests()
    assert recorded["body"]["subject"]["id"] == adapter.owner_id(ALICE)
    assert recorded["headers"]["X-Request-ID"] not in (None, "client-request-id")


def test_case_19_allowlist_and_no_token(start, stub, adapter):
    """Case 19: only allowlisted claims are sent, never the token."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", claims=ALLOWLIST)
    who = Identity(
        "alice-sub",
        {"eduperson_entitlement": [SUBGROUP], "email": "a@example.org", "groups": [NEAR_MISS], "scope": "openid"},
    )
    assert tes.create(who)[0] == 200
    (recorded,) = stub.requests()
    assert set(recorded["body"]["subject"]["properties"]["claims"]) == {"eduperson_entitlement"}
    assert not contains(recorded, adapter.token(who))
    assert recorded["headers"]["Authorization"] is None


def test_case_22_builtin_owner_rule(start, adapter):
    """Case 22: without a PDP the built-in owner rule applies (per TES)."""
    if adapter.name not in ("mock", "tesp", "funnel"):
        pytest.skip("per-TES expectation; add it with the adapter")
    tes = start()
    task_id = tes.create(BOB)[1]["id"]
    alice_task = tes.create(ALICE)[1]["id"]
    if adapter.name == "funnel":
        # Funnel keeps TaskAccess, whose default All shows every task to everyone.
        assert tes.call("GET", f"/tasks/{task_id}", ALICE)[0] == 200
        assert sorted(t["id"] for t in tes.call("GET", "/tasks", BOB)[1]["tasks"]) == sorted([task_id, alice_task])
        return
    assert tes.call("GET", f"/tasks/{task_id}", ALICE)[0] == 404
    assert [t["id"] for t in tes.call("GET", "/tasks", BOB)[1]["tasks"]] == [task_id]


def _needs_userinfo(adapter):
    if "userinfo" not in adapter.features:
        pytest.skip("adapter has no userinfo support")


def test_case_06b_userinfo_claims(start, stub, oidc, adapter):
    """Case 6b: claims only in userinfo count; in both, the token value wins (rule and PDP)."""
    _needs_userinfo(adapter)
    stub.script(default=ALLOW)
    tes = start(
        decision_service="stub",
        claims=ALLOWLIST,
        required_claim=RequiredClaim("eduperson_entitlement", (SUBGROUP,)),
        userinfo=True,
    )
    only_userinfo = Identity("u1-sub", {"scope": SCOPE}, {"eduperson_entitlement": [SUBGROUP]})
    token_wins = Identity("u2-sub", {"eduperson_entitlement": [SUBGROUP]}, {"eduperson_entitlement": [NEAR_MISS]})
    token_loses = Identity("u3-sub", {"eduperson_entitlement": [NEAR_MISS]}, {"eduperson_entitlement": [SUBGROUP]})
    assert tes.create(only_userinfo)[0] == 200
    assert tes.create(token_wins)[0] == 200
    assert tes.create(token_loses)[0] == 403
    sent = [r["body"]["subject"]["properties"]["claims"] for r in stub.requests()]
    assert sent == [{"eduperson_entitlement": [SUBGROUP]}, {"eduperson_entitlement": [SUBGROUP]}]


@pytest.mark.parametrize(
    "behaviour",
    [{"sub": "mallory-sub"}, {"status": 500}, {"close": True}, {"delay": 3}, {"mode": "jwt"}],
    ids=["sub-mismatch", "500", "connection-dropped", "timeout", "application-jwt"],
)
def test_case_20_userinfo_failure_is_401(start, stub, oidc, adapter, behaviour):
    """Case 20: userinfo ``sub`` mismatch, failure, timeout or signed answer gives 401; PDP not called."""
    _needs_userinfo(adapter)
    if "sub" in behaviour and "opaque-tokens" in adapter.features:
        pytest.skip("opaque tokens carry no sub to compare userinfo with")
    if "delay" in behaviour and "userinfo-timeout" not in adapter.features:
        pytest.skip("adapter cannot bound userinfo calls by HookConfig.timeout")
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", userinfo=True, timeout=1.0)
    oidc.userinfo_behaviour(behaviour)
    assert tes.create(ALICE)[0] == 401
    assert tes.call("GET", "/tasks", ALICE)[0] == 401
    assert stub.requests() == []
    oidc.userinfo_behaviour()
    assert tes.create(ALICE)[0] == 200


def test_case_21_userinfo_cached(start, stub, oidc, adapter):
    """Case 21: two calls with one token cause one userinfo call.

    Only for TESes that cache userinfo (spec change 16: TESK looks it up on
    every request, so revocation takes effect at once).
    """
    _needs_userinfo(adapter)
    if "userinfo-cache" not in adapter.features:
        pytest.skip("this TES looks up userinfo on every request (no cache)")
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", userinfo=True)
    assert tes.create(ALICE)[0] == 200
    assert tes.call("GET", "/tasks", ALICE)[0] == 200
    token = hashlib.sha256(adapter.token(ALICE).encode()).hexdigest()[:16]
    assert [c["status"] for c in oidc.userinfo_calls() if c["token_sha256"] == token] == [200]

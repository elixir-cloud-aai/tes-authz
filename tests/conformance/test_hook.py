"""Hook conformance (layer 1): each TES against the recording stub.

Case numbers refer to spec draft 3, section 8.2. Cases that need userinfo
(6b, 20, 21), startup checks (23) or gRPC (24) need features the phase-1
mock TES lacks; they are listed in the README as phase-2 work.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.golden import diff, instantiate
from harness.stub_client import ALLOW, DENY, rule
from harness.tes import RequiredClaim

from .conftest import ALICE, BOB, CAROL, NEAR_MISS, SERVICE_CLIENT, SUBGROUP, VO, contains

pytestmark = pytest.mark.services

GOLDEN_CREATE = json.loads((Path(__file__).resolve().parents[2] / "golden" / "hook" / "create.json").read_text())
RULE = RequiredClaim("eduperson_entitlement", (), (VO + ":",))
ALLOWLIST = ("eduperson_entitlement",)


def test_case_02_service_info_open(start, stub):
    """Case 2: service-info answers without a token."""
    tes = start()
    assert tes.call("GET", "/service-info", None)[0] == 200


def test_case_05_rule_fails_pdp_not_called(start, stub):
    """Case 5/16: a failing claim rule gives 403 on all actions; no PDP call."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub", required_claim=RULE, claims=ALLOWLIST)
    assert tes.create(CAROL)[0] == 403
    assert tes.call("GET", "/tasks/x", CAROL)[0] == 403
    assert tes.call("GET", "/tasks", CAROL)[0] == 403
    assert tes.call("POST", "/tasks/x:cancel", CAROL)[0] == 403
    assert stub.requests() == []


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
    from harness.tes import Identity

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
    fixtures = {"subject_id": adapter.owner_id(ALICE), "sub": ALICE.sub, **adapter.subject_fixtures(ALICE)}
    assert diff(instantiate(GOLDEN_CREATE["request"], fixtures), recorded["body"]) == []
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
    stub.script(default=DENY, rules=[rule(ALLOW, action="ListTasks", resource_id="all")])
    tes = start(decision_service="stub")
    assert tes.create(ALICE)[0] == 403
    assert tes.call("GET", "/tasks", ALICE)[1]["tasks"] == []


def test_case_09_pdp_allows_foreign_get(start, stub):
    """Case 9: the PDP may allow reading another user's task."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub")
    task_id = tes.create(BOB)[1]["id"]
    assert tes.call("GET", f"/tasks/{task_id}", ALICE)[0] == 200


def test_case_10_pdp_denies_get_and_cancel(start, stub):
    """Case 10: deny on get and cancel gives 404 and leaves the task unchanged."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub")
    task_id = tes.create(BOB)[1]["id"]
    stub.script(default=DENY)
    assert tes.call("GET", f"/tasks/{task_id}", ALICE)[0] == 404
    assert tes.call("POST", f"/tasks/{task_id}:cancel", ALICE)[0] == 404
    stub.script(default=ALLOW)
    assert tes.call("GET", f"/tasks/{task_id}?view=BASIC", BOB)[1]["state"] == "QUEUED"


def test_case_10b_get_allowed_cancel_denied(start, stub):
    """Case 10b: cancel denied but get allowed gives 403."""
    stub.script(default=ALLOW, rules=[rule(DENY, action="CancelTask")])
    tes = start(decision_service="stub")
    task_id = tes.create(BOB)[1]["id"]
    assert tes.call("POST", f"/tasks/{task_id}:cancel", ALICE)[0] == 403


@pytest.mark.parametrize("decision", [ALLOW, DENY], ids=["allow", "deny"])
def test_case_11_missing_task(start, stub, decision):
    """Case 11: a missing task gives 404; the PDP is called without properties."""
    stub.script(default=decision)
    tes = start(decision_service="stub")
    assert tes.call("GET", "/tasks/no-such-task", ALICE)[0] == 404
    (recorded,) = stub.requests()
    assert recorded["body"]["resource"]["id"] == "no-such-task"
    assert recorded["body"]["resource"]["properties"] == {}
    assert recorded["body"]["action"]["properties"] == {"view": "MINIMAL"}


@pytest.mark.parametrize("decision", [ALLOW, DENY], ids=["allow", "deny"])
def test_case_11c_cancel_parity(start, stub, decision):
    """Case 11c: cancel on a missing task asks CancelTask then GetTask, like a denied existing task."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub")
    task_id = tes.create(BOB)[1]["id"]
    stub.reset()
    stub.script(default=decision)
    assert tes.call("POST", "/tasks/no-such-task:cancel", ALICE)[0] == 404
    missing = stub.requests()
    assert [r["body"]["action"]["name"] for r in missing] == ["CancelTask", "GetTask"]
    for r in missing:
        assert r["body"]["resource"] == {"type": "tes_task", "id": "no-such-task", "properties": {}}
        assert r["body"]["action"]["properties"] == {}
    request_ids = [r["headers"]["X-Request-ID"] for r in missing]
    assert None not in request_ids and len(set(request_ids)) == 2
    if decision is DENY:
        stub.reset()
        stub.script(default=DENY)
        assert tes.call("POST", f"/tasks/{task_id}:cancel", ALICE)[0] == 404
        assert [r["body"]["action"]["name"] for r in stub.requests()] == ["CancelTask", "GetTask"]


def test_request_shape(start, stub, adapter):
    """Spec section 3.7: action properties always present, no properties on list sets, no null subject keys."""
    stub.script(default=ALLOW, rules=[rule(DENY, action="ListTasks", resource_id="all")])
    tes = start(decision_service="stub")
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
    assert by_action["CreateTask"][0]["action"]["properties"] == {}
    assert by_action["GetTask"][0]["action"]["properties"] == {"view": "BASIC"}
    assert set(by_action["GetTask"][0]["resource"]["properties"]) == {"owner", "state", "tags"}
    assert by_action["CancelTask"][0]["action"]["properties"] == {}
    for body in by_action["ListTasks"]:
        assert body["action"]["properties"] == {"view": "FULL"}
        assert "properties" not in body["resource"]
    request_ids = [r["headers"]["X-Request-ID"] for r in recorded]
    assert len(set(request_ids)) == len(request_ids)


def test_case_11b_pdp_down_same_answer(start, stub):
    """Case 11b: with the PDP down, missing and existing tasks both give 503."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub")
    task_id = tes.create(ALICE)[1]["id"]
    stub.script(default={"close": True})
    assert tes.call("GET", f"/tasks/{task_id}", ALICE)[0] == 503
    assert tes.call("GET", "/tasks/no-such-task", ALICE)[0] == 503


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


def test_case_12_all_scope_lists_everything(start, stub):
    """Case 12: the 'all' scope lists every task, complete, no duplicates."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub")
    created = [tes.create(who)[1]["id"] for who in (ALICE, BOB, ALICE, BOB, ALICE)]
    ids = _pages(tes, ALICE, 2)
    assert sorted(ids) == sorted(created) and len(ids) == len(set(ids))


def test_case_13_own_scope_lists_own_tasks(start, stub):
    """Case 13: the 'own' scope lists only own tasks across pages."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub")
    created = {who.sub: [] for who in (ALICE, BOB)}
    for who in (ALICE, BOB, ALICE, BOB, ALICE):
        created[who.sub].append(tes.create(who)[1]["id"])
    stub.script(default=ALLOW, rules=[rule(DENY, action="ListTasks", resource_id="all")])
    ids = _pages(tes, ALICE, 2)
    assert sorted(ids) == sorted(created[ALICE.sub]) and len(ids) == len(set(ids))


def test_case_14_both_sets_denied(start, stub):
    """Case 14: both sets denied gives 403 after asking 'all' and 'own'."""
    stub.script(default=DENY)
    tes = start(decision_service="stub")
    assert tes.call("GET", "/tasks", ALICE)[0] == 403
    assert {r["body"]["resource"]["id"] for r in stub.requests()} == {"all", "own"}


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
    """Case 15: a PDP 500 gives 503 on get, cancel and list as well, and changes nothing."""
    stub.script(default=ALLOW)
    tes = start(decision_service="stub")
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


def test_case_18_subject_from_token_only(start, stub):
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
    assert recorded["body"]["subject"]["id"] == ALICE.sub
    assert recorded["headers"]["X-Request-ID"] not in (None, "client-request-id")


def test_case_19_allowlist_and_no_token(start, stub, adapter):
    """Case 19: only allowlisted claims are sent, never the token."""
    from harness.tes import Identity

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
    if adapter.name not in ("mock", "tesp"):
        pytest.skip("per-TES expectation; add it with the adapter")
    tes = start()
    task_id = tes.create(BOB)[1]["id"]
    tes.create(ALICE)
    assert tes.call("GET", f"/tasks/{task_id}", ALICE)[0] == 404
    assert [t["id"] for t in tes.call("GET", "/tasks", BOB)[1]["tasks"]] == [task_id]

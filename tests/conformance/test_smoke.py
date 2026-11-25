"""Smoke (layer 3): each TES against each real engine, reference policy.

One allow and one deny per cell, plus the missing-task case that the
OpenFGA shim must turn into 404 rather than 503 (review 2, finding 3), and
the owner-only rule: the entitlement is needed only to create, owners keep
their tasks after losing it, foreign tasks are 404.
"""

from __future__ import annotations

import pytest

from harness.engines import ENGINES
from harness.tes import Identity

from .conftest import ALICE, BOB, CAROL, SCOPE

ALICE_REVOKED = Identity(ALICE.sub, {"scope": SCOPE})
"""Alice after her entitlement was revoked: the same owner, no entitlement."""

pytestmark = pytest.mark.services


@pytest.mark.parametrize("engine", list(ENGINES))
def test_smoke(services, start, engine):
    """Each TES with each engine: allow, deny, missing task 404, list scopes."""
    tes = start(decision_service=engine, claims=("eduperson_entitlement",))
    status, body = tes.create(ALICE)
    assert status == 200, body
    assert tes.create(CAROL)[0] == 403
    assert tes.call("GET", f"/tasks/{body['id']}", ALICE)[0] == 200
    assert tes.call("GET", f"/tasks/{body['id']}", CAROL)[0] == 404
    assert tes.call("GET", "/tasks/no-such-task", ALICE)[0] == 404
    assert tes.call("POST", "/tasks/no-such-task:cancel", ALICE)[0] == 404
    assert [t["id"] for t in tes.call("GET", "/tasks", ALICE)[1]["tasks"]] == [body["id"]]
    assert tes.call("GET", "/tasks", CAROL) == (200, {"tasks": []})


@pytest.mark.parametrize("engine", list(ENGINES))
def test_smoke_owner_only(services, start, engine):
    """Each TES with each engine: the entitlement is needed only to create; owners keep their tasks."""
    tes = start(decision_service=engine, claims=("eduperson_entitlement",))
    task_id = tes.create(ALICE)[1]["id"]
    bob_task = tes.create(BOB)[1]["id"]
    assert tes.create(ALICE_REVOKED)[0] == 403
    assert tes.call("GET", f"/tasks/{task_id}", ALICE_REVOKED)[0] == 200
    assert [t["id"] for t in tes.call("GET", "/tasks", ALICE_REVOKED)[1]["tasks"]] == [task_id]
    assert tes.call("GET", f"/tasks/{bob_task}", ALICE)[0] == 404
    assert tes.call("POST", f"/tasks/{bob_task}:cancel", ALICE)[0] == 404
    assert tes.call("POST", f"/tasks/{task_id}:cancel", ALICE_REVOKED)[0] == 200

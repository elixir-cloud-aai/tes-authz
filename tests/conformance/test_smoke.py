"""Smoke (layer 3): each TES against each real engine, reference policy.

One allow and one deny per cell, plus the missing-task case that the
OpenFGA shim must turn into 404 rather than 503 (review 2, finding 3).
"""

from __future__ import annotations

import pytest

from harness.engines import ENGINES

from .conftest import ALICE, CAROL

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
    assert tes.call("GET", "/tasks", CAROL)[0] == 403

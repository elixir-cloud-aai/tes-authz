"""The mock TES's startup checks and list scope parsing (spec sections 3.5 and 4.2), without services."""

from __future__ import annotations

from typing import Any

import pytest

from tes.mock import server

PDP = "http://127.0.0.1:1/access/v1/evaluation"


@pytest.mark.parametrize(
    "settings",
    [
        server.Settings(),
        server.Settings(pdp_url=PDP),
        server.Settings(pdp_url=PDP, operations=("create", "get", "list", "cancel")),
        server.Settings(pdp_url=PDP, operations=("create", "list"), failure={"list": "open", "get": "closed"}),
        server.Settings(pdp_url=PDP, failure={"create": "closed"}),
    ],
)
def test_valid_settings_start(settings):
    """Default, all four operations, and per-operation failure modes pass the startup checks."""
    server.check_settings(settings)


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        (server.Settings(pdp_url=PDP, operations=("get",)), "must contain create"),
        (server.Settings(pdp_url=PDP, operations=()), "must contain create"),
        (server.Settings(pdp_url=PDP, operations=("create", "delete")), "unknown operation"),
        (server.Settings(pdp_url=PDP, failure={"service-info": "open"}), "unknown operation"),
        (server.Settings(pdp_url=PDP, failure={"get": "allow"}), "unknown failure mode"),
        (server.Settings(pdp_url=PDP, failure={"create": "open"}), "create must be closed"),
        (server.Settings(operations=("create", "get")), "need authz.decisionService.url"),
        (server.Settings(failure={"get": "open"}), "need authz.decisionService.url"),
    ],
)
def test_invalid_settings_refuse_to_start(settings, message):
    """The TES refuses to start on a bad operation switch or failure mode."""
    with pytest.raises(ValueError, match=message):
        server.check_settings(settings)


def test_start_runs_the_checks():
    """``start()`` refuses settings that fail the checks before it listens."""
    with pytest.raises(ValueError, match="must contain create"):
        server.start(server.Settings(pdp_url=PDP, operations=("list",)))


@pytest.mark.parametrize(
    ("answer", "scope"),
    [
        ({"decision": False}, "none"),
        ({"decision": False, "context": {"tes": {"list_scope": "all"}}}, "none"),
        ({"decision": True}, "own"),
        ({"decision": True, "context": {}}, "own"),
        ({"decision": True, "context": {"tes": {}}}, "own"),
        ({"decision": True, "context": {"tes": {"reason": "x"}}}, "own"),
        ({"decision": True, "context": {"tes": {"list_scope": "own"}}}, "own"),
        ({"decision": True, "context": {"tes": {"list_scope": "all"}}}, "all"),
        ({"decision": True, "context": {"tes": {"list_scope": "none"}}}, "none"),
    ],
)
def test_list_scope(answer: dict[str, Any], scope):
    """A deny is ``none``, a plain allow ``own``; ``context.tes.list_scope`` sets the scope of an allow."""
    assert server.list_scope(answer) == scope


@pytest.mark.parametrize(
    "answer",
    [
        {"decision": True, "context": "x"},
        {"decision": True, "context": {"tes": []}},
        {"decision": True, "context": {"tes": {"list_scope": "group:x"}}},
        {"decision": True, "context": {"tes": {"list_scope": ["all"]}}},
        {"decision": True, "context": {"tes": {"list_scope": None}}},
    ],
)
def test_malformed_list_scope_is_a_failed_decision(answer):
    """An unknown or malformed list scope is a failed decision (503 when failing closed)."""
    with pytest.raises(server.DecisionServiceError):
        server.list_scope(answer)

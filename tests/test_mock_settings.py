"""The mock TES's startup checks and list scope parsing (spec sections 3.5 and 4.2), without services."""

from __future__ import annotations

import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
        server.Settings(operations=["create"]),  # type: ignore[arg-type]
    ],
)
def test_valid_settings_start(settings: server.Settings) -> None:
    """Case 30: default, all four operations, and per-operation failure modes pass the startup checks."""
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
        (server.Settings(operations=("get",)), "need authz.decisionService.url"),
        (server.Settings(pdp_url=PDP, operations=("create", "get", "get")), "twice"),
    ],
)
def test_invalid_settings_refuse_to_start(settings: server.Settings, message: str) -> None:
    """Case 30: the TES refuses to start on a bad operation switch or failure mode."""
    with pytest.raises(ValueError, match=message):
        server.check_settings(settings)


def test_start_runs_the_checks() -> None:
    """Case 30: ``start()`` refuses settings that fail the checks before it listens."""
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
def test_list_scope(answer: dict[str, Any], scope: str) -> None:
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
def test_malformed_list_scope_is_a_failed_decision(answer: dict[str, Any]) -> None:
    """An unknown or malformed list scope is a failed decision (503 when failing closed)."""
    with pytest.raises(server.DecisionServiceError):
        server.list_scope(answer)


def test_fail_open_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Case 29: a failed decision that falls back to the owner rule is logged, without claim values."""
    hook = server.Hook(
        server.Settings(pdp_url=PDP, timeout=0.5, operations=("create", "get"), failure={"get": "open"}),
        server.Store(),
    )
    caller = server.Principal({"sub": "u", "secret-claim": "do-not-log"}, owner_id="u")
    with caplog.at_level(logging.WARNING, logger="tes-authz-mock-tes"):
        assert hook.task_decision("get", caller, "t1", None, {}) == (False, False)
    assert "get falls back to the owner rule" in caplog.text
    assert "do-not-log" not in caplog.text


def test_fail_closed_raises() -> None:
    """Case 15: a failed decision that fails closed raises (503)."""
    hook = server.Hook(server.Settings(pdp_url=PDP, timeout=0.5, operations=("create", "get")), server.Store())
    with pytest.raises(server.DecisionServiceError):
        hook.task_decision("get", server.Principal({"sub": "u"}, owner_id="u"), "t1", None, {})


def test_task_without_owner_counts_as_missing() -> None:
    """Spec section 3.3: a task without an exact owner is asked about as missing and never served or listed."""
    store = server.Store()
    for task_id, owner in (("t-alice", "alice"), ("t-bob", "bob"), ("t-legacy", "")):
        store.tasks[task_id] = {"id": task_id, "state": "QUEUED", "_owner": owner}
        store.order[task_id] = len(store.order)
    hook = server.Hook(server.Settings(pdp_url=PDP, operations=("create", "get", "list", "cancel")), store)
    asked: list[dict[str, Any]] = []

    def allow_all(p: server.Principal, action: str, resource: dict[str, Any], aprops: Any = None) -> dict[str, Any]:
        asked.append(resource)
        return {"decision": True, "context": {"tes": {"list_scope": "all"}}}

    hook.ask = allow_all  # type: ignore[method-assign]
    alice = server.Principal({"sub": "alice"}, owner_id="alice")
    with pytest.raises(server.HttpError) as got:
        hook.get(alice, "t-legacy", "MINIMAL")
    with pytest.raises(server.HttpError) as cancelled:
        hook.cancel(alice, "t-legacy")
    assert (got.value.status, cancelled.value.status) == (404, 404)
    assert [r["properties"] for r in asked] == [{}, {}]
    assert store.tasks["t-legacy"]["state"] == "QUEUED"
    assert [t["id"] for t in hook.list(alice, 10, None, "MINIMAL")["tasks"]] == ["t-alice", "t-bob"]


class _TruncatingPdp(BaseHTTPRequestHandler):
    """A decision service that announces a longer body than it sends."""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Silence access logs.

        Args:
            format: The format string.
            *args: The format arguments.
        """

    def do_POST(self) -> None:
        """Answer with a truncated body and close the connection."""
        self.rfile.read(min(int(self.headers.get("Content-Length", "0")), server.MAX_BODY_BYTES))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "100")
        self.end_headers()
        self.wfile.write(b'{"decision"')
        self.close_connection = True


def test_truncated_answer_is_a_failed_decision() -> None:
    """Case 15: a body shorter than announced is a failed decision (503 or the fallback), not a dropped call."""
    pdp = ThreadingHTTPServer(("127.0.0.1", 0), _TruncatingPdp)
    threading.Thread(target=pdp.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{pdp.server_address[1]}/access/v1/evaluation"
        hook = server.Hook(server.Settings(pdp_url=url, timeout=2.0), server.Store())
        with pytest.raises(server.DecisionServiceError):
            hook.ask(server.Principal({"sub": "u"}, owner_id="u"), "CreateTask", {"type": "tes_task_set", "id": "own"})
    finally:
        pdp.shutdown()
        pdp.server_close()

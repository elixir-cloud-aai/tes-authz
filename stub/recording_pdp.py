"""Recording stub decision service for hook conformance tests (layer 1).

The stub serves the AuthZEN Access Evaluation endpoint, records every
request (body and selected headers) and answers with scripted responses.
A test scripts it through a control API on the same port; a TES never
calls the control API.

Endpoints:
    POST /access/v1/evaluation        record and answer
    GET  /.well-known/authzen-configuration
    GET  /health
    PUT  /_control/script             set the script (see below)
    GET  /_control/requests           recorded requests, oldest first
    POST /_control/reset              clear script and recordings

Script format::

    {"default": <response>,
     "rules": [{"match": {"action": "GetTask", "resource_type": "tes_task",
                          "resource_id": "t1", "subject_id": "alice"},
                "response": <response>}]}

The first rule whose ``match`` keys all equal the request wins; otherwise
``default`` applies (initially ``{"body": {"decision": false}}``). A
response is ``{"status": 200, "body": {...}}``, ``{"status": 200,
"raw": "text"}``, optionally with ``"delay": <seconds>`` (to provoke
timeouts) or ``"close": true`` (drop the connection without an answer).

Settings (environment): STUB_PORT (default 8080).
"""

from __future__ import annotations

import copy
import json
import logging
import os
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

RECORDED_HEADERS = ("X-Request-ID", "Authorization", "Content-Type", "traceparent")
"""Headers the stub records; ``Authorization`` is recorded as present/absent only."""

DEFAULT_RESPONSE: dict[str, Any] = {"status": 200, "body": {"decision": False}}

log = logging.getLogger("tes-authz-stub")


class State:
    """Script and recordings, shared by all handler threads."""

    def __init__(self) -> None:
        """Start with the default script and no recordings."""
        self.lock = threading.Lock()
        self.script: dict[str, Any] = {"default": DEFAULT_RESPONSE, "rules": []}
        self.requests: list[dict[str, Any]] = []

    def reset(self) -> None:
        """Clear script and recordings."""
        with self.lock:
            self.script = {"default": DEFAULT_RESPONSE, "rules": []}
            self.requests = []

    def respond(self, body: Any, headers: dict[str, str | None]) -> dict[str, Any]:
        """Record a request and pick its scripted response.

        Args:
            body: The decoded request body (or the raw text if not JSON).
            headers: The recorded headers.

        Returns:
            The response specification.
        """
        keys = request_keys(body)
        with self.lock:
            self.requests.append({"time": time.time(), "headers": headers, "body": body})
            for rule in self.script.get("rules", []):
                match = rule.get("match", {})
                if all(keys.get(key) == value for key, value in match.items()):
                    return copy.deepcopy(rule["response"])
            return copy.deepcopy(self.script.get("default", DEFAULT_RESPONSE))


def request_keys(body: Any) -> dict[str, Any]:
    """Extract the keys that script rules can match on.

    Args:
        body: The decoded request body.

    Returns:
        A flat map of match keys.
    """
    if not isinstance(body, dict):
        return {}

    def part(name: str) -> dict[str, Any]:
        value = body.get(name)
        return value if isinstance(value, dict) else {}

    return {
        "action": part("action").get("name"),
        "resource_type": part("resource").get("type"),
        "resource_id": part("resource").get("id"),
        "subject_id": part("subject").get("id"),
    }


def make_handler(state: State) -> type[BaseHTTPRequestHandler]:
    """Build the handler class bound to one state.

    Args:
        state: The shared state.

    Returns:
        The handler class.
    """

    class Handler(BaseHTTPRequestHandler):
        """Stub PDP handler."""

        server_version = "tes-authz-stub"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            """Route access logs to the module logger.

            Args:
                format: The format string.
                *args: The format arguments.
            """
            log.debug(format, *args)

        def _send_json(self, status: int, body: Any) -> None:
            self._send_raw(status, json.dumps(body), "application/json")

        def _send_raw(self, status: int, text: str, content_type: str) -> None:
            data = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> tuple[Any, bool]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length > 0 else b""
            try:
                return json.loads(raw), True
            except ValueError:
                return raw.decode("utf-8", "replace"), False

        def do_GET(self) -> None:
            """Serve metadata, health and recordings."""
            if self.path == "/health":
                self._send_json(HTTPStatus.OK, {"status": "ok"})
            elif self.path == "/.well-known/authzen-configuration":
                host = self.headers.get("Host", "localhost")
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "policy_decision_point": f"http://{host}",
                        "access_evaluation_endpoint": f"http://{host}/access/v1/evaluation",
                    },
                )
            elif self.path == "/_control/requests":
                with state.lock:
                    self._send_json(HTTPStatus.OK, state.requests)
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_PUT(self) -> None:
            """Set the script."""
            if self.path != "/_control/script":
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            script, ok = self._body()
            if not ok or not isinstance(script, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "script must be a JSON object"})
                return
            with state.lock:
                state.script = {"default": script.get("default", DEFAULT_RESPONSE), "rules": script.get("rules", [])}
            self._send_json(HTTPStatus.OK, state.script)

        def do_POST(self) -> None:
            """Answer evaluations and reset requests."""
            if self.path == "/_control/reset":
                state.reset()
                self._send_json(HTTPStatus.OK, {"status": "reset"})
                return
            if self.path != "/access/v1/evaluation":
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            body, _ = self._body()
            headers: dict[str, str | None] = {name: self.headers.get(name) for name in RECORDED_HEADERS}
            if headers["Authorization"] is not None:
                headers["Authorization"] = "<present>"
            response = state.respond(body, headers)
            if response.get("delay"):
                time.sleep(float(response["delay"]))
            if response.get("close"):
                self.close_connection = True
                return
            status = int(response.get("status", 200))
            if "raw" in response:
                self._send_raw(status, str(response["raw"]), response.get("content_type", "application/json"))
            else:
                self._send_json(status, response.get("body", {"decision": False}))

    return Handler


def make_server(port: int, host: str = "0.0.0.0") -> tuple[ThreadingHTTPServer, State]:  # noqa: S104
    """Create a stub server (not yet serving).

    Args:
        port: The TCP port (0 picks a free one).
        host: The address to bind.

    Returns:
        The server and its state.
    """
    state = State()
    server = ThreadingHTTPServer((host, port), make_handler(state))
    server.daemon_threads = True
    return server, state


def main() -> None:
    """Run the stub until interrupted."""
    logging.basicConfig(level=os.environ.get("STUB_LOG_LEVEL", "INFO"))
    server, _ = make_server(int(os.environ.get("STUB_PORT", "8080")))
    log.info("listening on port %d", server.server_address[1])
    server.serve_forever()


if __name__ == "__main__":
    main()

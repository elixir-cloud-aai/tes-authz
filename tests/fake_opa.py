"""A stand-in for ``opa run --server`` in the tests of ``shims/opa_service.py``.

Takes OPA's command line, writes it as JSON to the file named by
``FAKE_OPA_ARGS`` (if set), and serves ``/health`` and the decision path
(``tes/authz/allow``) on the ``--addr`` it is given, allowing exactly the
requests whose subject ID is ``allowed``. With ``FAKE_OPA_EXIT`` set, it
exits at once with that status instead; with ``FAKE_OPA_UNHEALTHY`` set,
its health check answers ``503`` (OPA never gets ready); with
``FAKE_OPA_DELAY`` (seconds), it answers decisions that much later.
"""

from __future__ import annotations

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

MAX_BODY_BYTES = 1024 * 1024
"""Largest request body accepted (as the front's default)."""


class Handler(BaseHTTPRequestHandler):
    """OPA's health check and Data API, as far as the front uses them."""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Keep the test output quiet.

        Args:
            format: The format string.
            *args: The format arguments.
        """

    def _send(self, body: Any) -> None:
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        """Answer the health check (``503`` with ``FAKE_OPA_UNHEALTHY``)."""
        if os.environ.get("FAKE_OPA_UNHEALTHY"):
            self.send_error(503)
            return
        self._send({})

    def do_POST(self) -> None:
        """Allow exactly the subject ID ``allowed``, at the decision path only."""
        if self.path != "/v1/data/tes/authz/allow":
            self.send_error(404)
            return
        length = int(self.headers["Content-Length"])
        if length < 0 or length > MAX_BODY_BYTES:
            self.send_error(400)
            return
        body = json.loads(self.rfile.read(length))
        time.sleep(float(os.environ.get("FAKE_OPA_DELAY", "0")))
        self._send({"result": body["input"]["subject"]["id"] == "allowed"})


def main() -> None:
    """Record the arguments, then serve or exit."""
    args = sys.argv[1:]
    if os.environ.get("FAKE_OPA_ARGS"):
        with open(os.environ["FAKE_OPA_ARGS"], "w", encoding="utf-8") as handle:
            json.dump(args, handle)
    if os.environ.get("FAKE_OPA_EXIT"):
        sys.exit(int(os.environ["FAKE_OPA_EXIT"]))
    addr = next(a.split("=", 1)[1] for a in args if a.startswith("--addr="))
    host, port = addr.rsplit(":", 1)
    HTTPServer((host, int(port)), Handler).serve_forever()


if __name__ == "__main__":
    main()

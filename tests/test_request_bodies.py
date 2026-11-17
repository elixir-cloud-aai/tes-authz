"""Request body limits of the in-process stub and mock TES (no containers).

The shims are checked against the compose services in ``test_findings.py``.
"""

from __future__ import annotations

import http.client
import threading
from collections.abc import Iterator
from http import HTTPStatus

import pytest

from stub.recording_pdp import MAX_BODY_BYTES as STUB_MAX_BODY_BYTES
from stub.recording_pdp import make_server
from tes.mock import server as mock_tes


def _declare_length(port: int, method: str, path: str, length: int) -> int:
    """Send headers that declare a body of ``length`` bytes, without the body.

    Args:
        port: The server's loopback port.
        method: HTTP method.
        path: Request path.
        length: The declared ``Content-Length``.

    Returns:
        The response status; a server that waited for the body would time out.
    """
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.putrequest(method, path)
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(length))
        connection.endheaders()
        return connection.getresponse().status
    finally:
        connection.close()


@pytest.fixture(scope="module")
def stub_port() -> Iterator[int]:
    """An in-process stub on a free loopback port."""
    server, _ = make_server(0, host="127.0.0.1")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def mock_tes_port() -> Iterator[int]:
    """An in-process mock TES on a free loopback port."""
    server, _ = mock_tes.start(mock_tes.Settings())
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.mark.parametrize(
    ("method", "path"),
    [("POST", "/access/v1/evaluation"), ("PUT", "/_control/script")],
)
def test_stub_rejects_long_bodies(stub_port: int, method: str, path: str) -> None:
    """The stub answers 413 for bodies over its limit, without reading them."""
    assert _declare_length(stub_port, method, path, STUB_MAX_BODY_BYTES + 1) == HTTPStatus.REQUEST_ENTITY_TOO_LARGE


@pytest.mark.parametrize(
    "path",
    [f"{mock_tes.PREFIX}/tasks", f"{mock_tes.PREFIX}/tasks/t1:cancel"],
)
def test_mock_tes_rejects_long_bodies(mock_tes_port: int, path: str) -> None:
    """The mock TES answers 413 for bodies over its limit, without reading them."""
    status = _declare_length(mock_tes_port, "POST", path, mock_tes.MAX_BODY_BYTES + 1)
    assert status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE

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

STUB_PATHS = [("POST", "/access/v1/evaluation"), ("PUT", "/_control/script")]
MOCK_TES_PATHS = [f"{mock_tes.PREFIX}/tasks", f"{mock_tes.PREFIX}/tasks/t1:cancel"]


def _request(port: int, method: str, path: str, headers: dict[str, str], body: bytes = b"") -> int:
    """Send a request with the given headers and body, as they are.

    Args:
        port: The server's loopback port.
        method: HTTP method.
        path: Request path.
        headers: Headers, e.g. a ``Content-Length`` that doesn't match the body.
        body: The bytes sent after the headers.

    Returns:
        The response status; a server that waited for more body would time out.
    """
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.putrequest(method, path)
        connection.putheader("Content-Type", "application/json")
        for name, value in headers.items():
            connection.putheader(name, value)
        connection.endheaders(body or None)
        return connection.getresponse().status
    finally:
        connection.close()


def _declare_length(port: int, method: str, path: str, length: int | str) -> int:
    """Send headers that declare a body of ``length`` bytes, without the body.

    Args:
        port: The server's loopback port.
        method: HTTP method.
        path: Request path.
        length: The declared ``Content-Length``.

    Returns:
        The response status.
    """
    return _request(port, method, path, {"Content-Length": str(length)})


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


@pytest.mark.parametrize(("method", "path"), STUB_PATHS)
def test_stub_rejects_long_bodies(stub_port: int, method: str, path: str) -> None:
    """The stub answers 413 for bodies over its limit, without reading them."""
    assert _declare_length(stub_port, method, path, STUB_MAX_BODY_BYTES + 1) == HTTPStatus.REQUEST_ENTITY_TOO_LARGE


@pytest.mark.parametrize("length", [-1, "abc"])
@pytest.mark.parametrize(("method", "path"), STUB_PATHS)
def test_stub_rejects_bad_lengths(stub_port: int, method: str, path: str, length: int | str) -> None:
    """The stub answers 400 for negative or non-numeric lengths, without reading."""
    assert _declare_length(stub_port, method, path, length) == HTTPStatus.BAD_REQUEST


def test_stub_reads_bodies_up_to_its_limit(stub_port: int) -> None:
    """A body of exactly the limit is read and answered."""
    body = b'"' + b"x" * (STUB_MAX_BODY_BYTES - 2) + b'"'
    status = _request(stub_port, "POST", "/access/v1/evaluation", {"Content-Length": str(len(body))}, body)
    assert status == HTTPStatus.OK


@pytest.mark.parametrize("path", MOCK_TES_PATHS)
def test_mock_tes_rejects_long_bodies(mock_tes_port: int, path: str) -> None:
    """The mock TES answers 413 for bodies over its limit, without reading them."""
    status = _declare_length(mock_tes_port, "POST", path, mock_tes.MAX_BODY_BYTES + 1)
    assert status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE


@pytest.mark.parametrize("length", [-1, "abc"])
@pytest.mark.parametrize("path", MOCK_TES_PATHS)
def test_mock_tes_rejects_bad_lengths(mock_tes_port: int, path: str, length: int | str) -> None:
    """The mock TES answers 400 for negative or non-numeric lengths, without reading."""
    assert _declare_length(mock_tes_port, "POST", path, length) == HTTPStatus.BAD_REQUEST


def test_mock_tes_requires_content_length(mock_tes_port: int) -> None:
    """The mock TES answers 411 for chunked bodies."""
    status = _request(mock_tes_port, "POST", MOCK_TES_PATHS[0], {"Transfer-Encoding": "chunked"}, b"0\r\n\r\n")
    assert status == HTTPStatus.LENGTH_REQUIRED


def test_mock_tes_reads_bodies_up_to_its_limit(mock_tes_port: int) -> None:
    """A body of exactly the limit is read; the request then fails AuthN (no token)."""
    body = b" " * (mock_tes.MAX_BODY_BYTES - 2) + b"{}"
    status = _request(mock_tes_port, "POST", MOCK_TES_PATHS[0], {"Content-Length": str(len(body))}, body)
    assert status == HTTPStatus.UNAUTHORIZED

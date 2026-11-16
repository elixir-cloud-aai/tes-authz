"""Shared fixtures: service availability and HTTP helpers."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

import pytest

from harness.engines import ENGINES, OPA_DATA_API, OPENFGA_API, STUB


def http(
    method: str, url: str, body: Any = None, headers: dict[str, str] | None = None, timeout: float = 10.0
) -> tuple[int, Any]:
    """Send a JSON request and return status and decoded body.

    Args:
        method: HTTP method.
        url: Target URL.
        body: JSON body, if any.
        headers: Extra headers.
        timeout: Timeout in seconds.

    Returns:
        Status and body (text if not JSON).
    """
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, raw.decode("utf-8", "replace")


def _base(url: str) -> str:
    return url.split("/access/")[0].split("/v1/")[0]


HEALTH = {
    "opa": _base(OPA_DATA_API.host_url) + "/health",
    "opa-front": _base(ENGINES["opa"].host_url) + "/health",
    "openfga": OPENFGA_API + "/healthz",
    "openfga-shim": _base(ENGINES["openfga"].host_url) + "/health",
    "stub": _base(STUB.host_url) + "/health",
}


@pytest.fixture(scope="session")
def services() -> None:
    """Wait for the compose services; skip (or fail if required) when absent."""
    required = os.environ.get("TES_AUTHZ_REQUIRE_SERVICES") == "1"
    deadline = time.monotonic() + (60 if required else 3)
    missing = list(HEALTH)
    while missing and time.monotonic() < deadline:
        for name in list(missing):
            try:
                with urllib.request.urlopen(HEALTH[name], timeout=1) as response:
                    if response.status == 200:
                        missing.remove(name)
            except (urllib.error.URLError, OSError):
                pass
        if missing:
            time.sleep(0.5)
    if missing:
        message = f"services not reachable: {', '.join(missing)} (run `make up`)"
        if required:
            pytest.fail(message)
        pytest.skip(message)

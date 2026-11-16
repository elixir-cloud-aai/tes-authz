"""Fixtures for the per-TES suites."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pytest

from harness.engines import STUB
from harness.stub_client import StubClient
from harness.tes import HookConfig, Identity, TesUnderTest, adapters

from ..conftest import http

VO = "urn:geant:lifescience-ri.eu:group:example-vo"
SUBGROUP = VO + ":analysts#login.aai.lifescience-ri.eu"
NEAR_MISS = "urn:geant:lifescience-ri.eu:group:example-vox#login.aai.lifescience-ri.eu"
SCOPE = "openid eduperson_entitlement"

ALICE = Identity("alice-sub", {"eduperson_entitlement": [SUBGROUP], "scope": SCOPE})
BOB = Identity("bob-sub", {"eduperson_entitlement": [SUBGROUP], "scope": SCOPE})
CAROL = Identity("carol-sub", {"eduperson_entitlement": [NEAR_MISS], "scope": SCOPE})
SERVICE_CLIENT = Identity("protes", {"scope": "openid"}, client_credentials=True)


@dataclass
class Client:
    """A started TES plus helpers.

    Attributes:
        tes: The adapter.
        url: The TES base URL.
    """

    tes: TesUnderTest
    url: str

    def call(
        self, method: str, path: str, who: Identity | None, body: Any = None, headers: dict[str, str] | None = None
    ) -> tuple[int, Any]:
        """Call the TES.

        Args:
            method: HTTP method.
            path: Path below the base URL.
            who: The caller (``None``: no token).
            body: JSON body.
            headers: Extra headers.

        Returns:
            Status and body.
        """
        all_headers = dict(headers or {})
        if who is not None:
            all_headers["Authorization"] = "Bearer " + self.tes.token(who)
        return http(method, self.url + path, body, all_headers)

    def create(self, who: Identity, task: dict[str, Any] | None = None) -> tuple[int, Any]:
        """Create a task.

        Args:
            who: The caller.
            task: The task (default: a minimal valid task).

        Returns:
            Status and body.
        """
        default = {"name": "t", "executors": [{"image": "docker.io/library/alpine:3.20", "command": ["true"]}]}
        return self.call("POST", "/tasks", who, task or default)


@pytest.fixture(params=adapters(), ids=lambda a: a.name)
def adapter(request: pytest.FixtureRequest) -> Iterator[TesUnderTest]:
    """Each TES under test in turn."""
    tes: TesUnderTest = request.param
    yield tes
    tes.stop()


@pytest.fixture
def stub(services) -> StubClient:
    """The recording stub, reset."""
    client = StubClient(STUB.host_url.removesuffix("/access/v1/evaluation"))
    client.reset()
    return client


@pytest.fixture
def start(adapter: TesUnderTest) -> Callable[..., Client]:
    """Start the TES under test with a given configuration."""

    def _start(**kwargs: Any) -> Client:
        return Client(adapter, adapter.start(HookConfig(**kwargs)))

    return _start


def contains(haystack: Any, needle: str) -> bool:
    """Tell whether a JSON value contains a string anywhere.

    Args:
        haystack: The JSON value.
        needle: The string.

    Returns:
        Whether it occurs.
    """
    return needle in json.dumps(haystack)

"""The "TES under test" interface for hook conformance and smoke tests.

Each TES lives in ``tes/<name>/adapter.py`` and exposes ``ADAPTER``, an
object implementing ``TesUnderTest``. The suites in
``tests/conformance/`` run against every adapter listed in
``TES_AUTHZ_TES`` (comma-separated; default ``mock``). Adding TESK, Funnel
or TESP in phase 2 means adding an adapter; the engine side, the stub and
the suites stay as they are.
"""

from __future__ import annotations

import importlib
import os
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class RequiredClaim:
    """The built-in claim rule (``authz.requiredClaim.*``).

    Attributes:
        name: Claim name (exact top-level name first, else dotted path).
        values: Exact values.
        prefixes: Raw string prefixes.
    """

    name: str
    values: tuple[str, ...] = ()
    prefixes: tuple[str, ...] = ()


@dataclass(frozen=True)
class HookConfig:
    """The TES-side AuthZ configuration of one test.

    Attributes:
        decision_service: Engine name from ``harness.engines`` (``stub``,
            ``opa``, ``openfga``) or ``None`` for the built-in owner rule.
        timeout: ``authz.decisionService.timeout`` in seconds.
        claims: ``authz.decisionService.claims`` (the allowlist).
        required_claim: ``authz.requiredClaim.*``, or ``None``.
        userinfo: ``auth.oidc.userinfo.enabled``.
        service_id: The service-info ID the TES reports.
    """

    decision_service: str | None = None
    timeout: float = 2.0
    claims: tuple[str, ...] = ()
    required_claim: RequiredClaim | None = None
    userinfo: bool = False
    service_id: str = "tes-authz-test"


@dataclass
class Identity:
    """A test user or client.

    Attributes:
        sub: The OIDC subject.
        claims: Extra access-token claims.
        userinfo: Claims only the userinfo endpoint returns.
        client_credentials: Whether this is a client-credentials token.
    """

    sub: str
    claims: dict[str, Any] = field(default_factory=dict)
    userinfo: dict[str, Any] = field(default_factory=dict)
    client_credentials: bool = False


class TesUnderTest(Protocol):
    """What a TES adapter provides to the suites."""

    name: str
    """Short name used in test IDs."""

    features: frozenset[str]
    """Optional features, e.g. ``keyset-cursor``, ``userinfo``, ``userinfo-cache``, ``grpc``."""

    def start(self, config: HookConfig) -> str:
        """(Re)start the TES with this configuration.

        Args:
            config: The AuthZ configuration.

        Returns:
            The TES base URL including ``/ga4gh/tes/v1``.
        """
        ...

    def stop(self) -> None:
        """Stop the TES."""
        ...

    def token(self, identity: Identity) -> str:
        """Return an access token the TES accepts for this identity.

        Args:
            identity: The identity.

        Returns:
            The bearer token.
        """
        ...

    def owner_id(self, identity: Identity) -> str:
        """Return the owner ID the TES stamps for this identity.

        Args:
            identity: The identity.

        Returns:
            The owner ID (``subject.id``).
        """
        ...

    def subject_fixtures(self, identity: Identity) -> dict[str, Any]:
        """Return per-TES values for golden placeholders of the subject.

        At least ``iss`` and ``client_id`` (``None`` where the TES cannot
        fill it, e.g. TESK for user tokens, spec section 6).

        Args:
            identity: The identity.

        Returns:
            Placeholder name to value.
        """
        ...


def adapters() -> list[TesUnderTest]:
    """Load the adapters named in ``TES_AUTHZ_TES``.

    Returns:
        The adapters.
    """
    names = [n.strip() for n in os.environ.get("TES_AUTHZ_TES", "mock").split(",") if n.strip()]
    return [importlib.import_module(f"tes.{name}.adapter").ADAPTER for name in names]

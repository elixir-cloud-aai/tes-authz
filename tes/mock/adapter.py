"""Adapter for the in-process mock TES (the phase-1 "TES under test").

The mock TES runs on the host, so it uses the mock issuer's host URL:
issuer ``harness.oidc.issuer_url("a")``, audience ``harness.oidc.AUDIENCE``,
and JWT access tokens from ``harness.oidc.OIDC``.
"""

from __future__ import annotations

from http.server import ThreadingHTTPServer
from typing import Any

from harness.engines import ENGINES, STUB
from harness.oidc import AUDIENCE, OIDC, default_claims, issuer_url
from harness.tes import HookConfig, Identity
from tes.mock import server

ISSUER = issuer_url("a")


class MockTes:
    """Runs ``tes.mock.server`` in a thread of the test process."""

    name = "mock"
    features = frozenset({"keyset-cursor", "userinfo"})

    def __init__(self) -> None:
        """Start without a running server."""
        self._server: ThreadingHTTPServer | None = None

    def start(self, config: HookConfig) -> str:
        """Start a fresh mock TES (empty store) with this configuration.

        Args:
            config: The AuthZ configuration.

        Returns:
            The base URL.
        """
        self.stop()
        pdp = None
        if config.decision_service == "stub":
            pdp = STUB.host_url
        elif config.decision_service is not None:
            pdp = ENGINES[config.decision_service].host_url
        rule = config.required_claim
        settings = server.Settings(
            pdp_url=pdp,
            timeout=config.timeout,
            claims=config.claims,
            rule_name=rule.name if rule else None,
            rule_values=rule.values if rule else (),
            rule_prefixes=rule.prefixes if rule else (),
            service_id=config.service_id,
            issuers=(ISSUER,),
            audience=AUDIENCE,
            userinfo=config.userinfo,
        )
        self._server, url = server.start(settings)
        return url

    def stop(self) -> None:
        """Stop the server if it runs."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def token(self, identity: Identity) -> str:
        """Mint a JWT access token at the mock issuer.

        Args:
            identity: The identity.

        Returns:
            The bearer token (without ``Bearer``).
        """
        return OIDC.token_for(identity)

    def owner_id(self, identity: Identity) -> str:
        """Return ``sub`` (single-issuer TES).

        Args:
            identity: The identity.

        Returns:
            The owner ID.
        """
        return identity.sub

    def subject_fixtures(self, identity: Identity) -> dict[str, Any]:
        """Return the issuer and client ID the tokens carry.

        Args:
            identity: The identity.

        Returns:
            Placeholder name to value.
        """
        claims = default_claims(identity)
        return {"iss": ISSUER, "client_id": claims.get("azp", claims.get("client_id"))}


ADAPTER = MockTes()

"""Adapter for the in-process mock TES (the phase-1 "TES under test")."""

from __future__ import annotations

import base64
import json
from http.server import ThreadingHTTPServer
from typing import Any

from harness.engines import ENGINES, STUB
from harness.tes import HookConfig, Identity
from tes.mock import server

ISSUER = "https://issuer.tes-authz.test/"


class MockTes:
    """Runs ``tes.mock.server`` in a thread of the test process."""

    name = "mock"
    features = frozenset({"keyset-cursor"})

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
        """Encode the test-only token.

        Args:
            identity: The identity.

        Returns:
            The bearer token (without ``Bearer``).
        """
        claims = {"iss": ISSUER, "sub": identity.sub, **identity.claims}
        if identity.client_credentials:
            claims.setdefault("client_id", identity.sub)
        else:
            claims.setdefault("azp", "tes-client")
        raw = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        return "mock." + raw

    def owner_id(self, identity: Identity) -> str:
        """Return ``sub`` (single-issuer TES).

        Args:
            identity: The identity.

        Returns:
            The owner ID.
        """
        return identity.sub

    def subject_fixtures(self, identity: Identity) -> dict[str, Any]:
        """Return the issuer and client ID the mock tokens carry.

        Args:
            identity: The identity.

        Returns:
            Placeholder name to value.
        """
        client = identity.sub if identity.client_credentials else "tes-client"
        return {"iss": ISSUER, "client_id": identity.claims.get("client_id", identity.claims.get("azp", client))}


ADAPTER = MockTes()

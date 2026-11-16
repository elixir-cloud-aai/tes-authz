"""Client for the mock OIDC issuer (``oidc/issuer.py``): tokens for TES adapters.

The issuer runs as compose service ``oidc`` (container ``tes-authz-oidc``)
and serves two issuers, ``a`` and ``b``. Their URLs depend on where the TES
runs, because the issuer derives its URL from the host name the TES uses:

* TES on the host: ``issuer_url("a")`` = ``http://127.0.0.1:18193/a``;
* TES on the compose network: ``issuer_url("a", NETWORK_BASE)`` =
  ``http://tes-authz-oidc:8080/a``.

Configure the TES with that issuer URL and the audience ``AUDIENCE``, and
mint tokens with the same ``base``::

    from harness.oidc import AUDIENCE, NETWORK_BASE, OIDC, issuer_url

    OIDC.token_for(identity, base=NETWORK_BASE)                  # JWT
    OIDC.token_for(identity, base=NETWORK_BASE, fmt="opaque")    # TESK

Tokens are cached per identity and options until ``reset()``, so one
identity presents the same token across calls (spec case 21).
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

from harness.tes import Identity

OIDC_PORT = int(os.environ.get("TES_AUTHZ_OIDC_PORT", "18193"))
"""Host port of the issuer (loopback)."""

HOST_BASE = f"http://127.0.0.1:{OIDC_PORT}"
"""Issuer base as seen from the host."""

NETWORK_BASE = "http://tes-authz-oidc:8080"
"""Issuer base as seen from containers on the compose network ``tes-authz_default``."""

ISSUERS = ("a", "b")
"""Issuer names; ``b`` is for multi-issuer cases (``<iss>|<sub>`` owners)."""

AUDIENCE = "tes-authz"
"""Default ``aud`` of minted tokens; configure TESes to require it."""

CLIENT_ID = "tes-client"
"""``azp`` of user tokens minted by ``token_for``."""


def issuer_url(name: str = "a", base: str = HOST_BASE) -> str:
    """Return an issuer URL (the ``iss`` claim and discovery base).

    Args:
        name: Issuer name.
        base: ``HOST_BASE`` or ``NETWORK_BASE`` (or another reachable base).

    Returns:
        The issuer URL, without trailing slash.
    """
    return f"{base}/{name}"


def default_claims(identity: Identity) -> dict[str, Any]:
    """Return the token claims ``token_for`` puts into a token for an identity.

    ``identity.claims`` plus ``azp`` (``CLIENT_ID``) for users, or
    ``client_id`` (= ``sub``) for client-credentials identities, unless the
    identity sets them itself.

    Args:
        identity: The identity.

    Returns:
        The claims (without ``iss``, ``sub``, ``aud``, ``exp``, ``iat``).
    """
    claims = dict(identity.claims)
    if identity.client_credentials:
        claims.setdefault("client_id", identity.sub)
    else:
        claims.setdefault("azp", CLIENT_ID)
    return claims


class OidcClient:
    """Mints tokens and scripts the mock issuer through its control API."""

    def __init__(self, base_url: str = HOST_BASE) -> None:
        """Bind to an issuer.

        Args:
            base_url: The issuer's base URL as seen from the test process.
        """
        self.base_url = base_url.rstrip("/")
        self._cache: dict[str, str] = {}

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self.base_url + path, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())

    def mint(self, sub: str, **options: Any) -> dict[str, Any]:
        """Mint a token with full control (see ``oidc/issuer.py`` for options).

        Args:
            sub: The subject.
            **options: ``issuer``, ``base``, ``format``, ``aud``, ``scope``,
                ``expires_in``, ``claims``, ``userinfo``, ``key``, ``alg``,
                ``header``.

        Returns:
            ``{"access_token", "token_type", "expires_in", "iss", "kid"}``.
        """
        answer: dict[str, Any] = self._call("POST", "/_control/tokens", {"sub": sub, **options})
        return answer

    def token_for(
        self,
        identity: Identity,
        *,
        issuer: str = "a",
        base: str = HOST_BASE,
        fmt: str = "jwt",
        aud: str | list[str] = AUDIENCE,
        userinfo: dict[str, Any] | None = None,
    ) -> str:
        """Return a (cached) access token for an identity.

        Token claims are ``default_claims(identity)``. Userinfo returns
        ``identity.userinfo`` for JWTs; for opaque tokens, which carry no
        claims, it returns ``identity.userinfo`` overlaid with the token
        claims (the token value wins, as in the resolved claim view).

        Args:
            identity: The identity.
            issuer: Issuer name.
            base: ``HOST_BASE`` or ``NETWORK_BASE``.
            fmt: ``jwt`` or ``opaque``.
            aud: The audience.
            userinfo: Explicit userinfo claims (overrides the default).

        Returns:
            The bearer token (without ``Bearer``).
        """
        claims = default_claims(identity)
        if userinfo is None:
            userinfo = dict(identity.userinfo) if fmt == "jwt" else {**identity.userinfo, **claims}
        request = {
            "sub": identity.sub,
            "issuer": issuer,
            "base": base,
            "format": fmt,
            "aud": aud,
            "claims": claims,
            "userinfo": userinfo,
        }
        key = json.dumps(request, sort_keys=True)
        if key not in self._cache:
            self._cache[key] = str(self._call("POST", "/_control/tokens", request)["access_token"])
        return self._cache[key]

    def reset(self, keys: bool = False) -> None:
        """Forget tokens, userinfo behaviours and calls (issuer and cache).

        Args:
            keys: Also renew every issuer's signing keys.
        """
        self._cache.clear()
        self._call("POST", "/_control/reset", {"keys": keys})

    def rotate(self, issuer: str = "a", keep_previous: bool = True) -> str:
        """Make a new active signing key.

        Args:
            issuer: Issuer name.
            keep_previous: Keep old keys in the JWKS; else they are retired at once.

        Returns:
            The new key ID.
        """
        self._cache.clear()
        return str(
            self._call("POST", "/_control/keys/rotate", {"issuer": issuer, "keep_previous": keep_previous})["kid"]
        )

    def retire(self, kid: str, issuer: str = "a") -> None:
        """Remove a key from the JWKS.

        Args:
            kid: The key ID.
            issuer: Issuer name.
        """
        self._cache.clear()
        self._call("POST", "/_control/keys/retire", {"issuer": issuer, "kid": kid})

    def jwks(self, issuer: str = "a") -> dict[str, Any]:
        """Return an issuer's JWK Set.

        Args:
            issuer: Issuer name.

        Returns:
            The JWK Set.
        """
        answer: dict[str, Any] = self._call("GET", f"/{issuer}/jwks")
        return answer

    def userinfo_behaviour(
        self, default: dict[str, Any] | None = None, subjects: dict[str, dict[str, Any]] | None = None
    ) -> None:
        """Script userinfo answers (see ``oidc/issuer.py`` for the format).

        Args:
            default: Behaviour for every subject not listed (default: JSON, 200).
            subjects: Behaviour per subject.
        """
        self._call("PUT", "/_control/userinfo", {"default": default or {"mode": "json"}, "subjects": subjects or {}})

    def userinfo_calls(self) -> list[dict[str, Any]]:
        """Return the recorded userinfo calls.

        Returns:
            ``{"time", "issuer", "sub", "token_sha256", "status", "mode"}``, oldest first.
        """
        calls: list[dict[str, Any]] = self._call("GET", "/_control/userinfo-calls")
        return calls


OIDC = OidcClient()
"""The issuer as seen from the test process; adapters use it in ``token()``."""

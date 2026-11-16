"""The mock TES against the mock OIDC issuer: AuthN as a real TES does it.

These pin what every adapter relies on: tokens from the issuer validate
through discovery and JWKS, bad tokens are refused, key rotation works, the
userinfo cache behaves as spec section 3.6 says, and a TES pinned to both
issuers stamps ``<iss>|<sub>`` owners (spec section 3.1). They run the mock
TES directly, so they need no adapter.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from harness.engines import STUB
from harness.oidc import AUDIENCE, OidcClient, issuer_url
from harness.stub_client import ALLOW, StubClient
from tes.mock import server

from ..conftest import http

pytestmark = pytest.mark.services

TASK = {"name": "t", "executors": [{"image": "docker.io/library/alpine:3.20"}]}


@pytest.fixture
def tes_for() -> Iterator[Callable[..., str]]:
    """Start mock TESes pinned to given issuers; stop them afterwards."""
    started = []

    def _start(*issuers: str, pdp: str | None = None, **settings: Any) -> str:
        srv, url = server.start(server.Settings(pdp_url=pdp, issuers=issuers, audience=AUDIENCE, **settings))
        started.append(srv)
        return url

    yield _start
    for srv in started:
        srv.shutdown()
        srv.server_close()


def _create(url: str, token: str | None) -> int:
    headers = {"Authorization": "Bearer " + token} if token is not None else {}
    return http("POST", url + "/tasks", TASK, headers)[0]


@pytest.mark.parametrize(
    "options",
    [
        {"alg": "none"},
        {"key": "unpublished"},
        {"aud": "other-service"},
        {"expires_in": -3600},
        {"issuer": "b"},
        {"issuer": "b", "claims": {"iss": issuer_url("a")}},
        {"header": {"kid": "no-such-key"}},
    ],
    ids=["alg-none", "unpublished-key", "wrong-aud", "expired", "other-issuer", "forged-iss", "unknown-kid"],
)
def test_bad_tokens_refused(oidc: OidcClient, tes_for, options):
    """Tokens a TES must refuse get 401."""
    url = tes_for(issuer_url("a"))
    assert _create(url, oidc.mint("alice", **options)["access_token"]) == 401


def test_missing_and_opaque_tokens_refused(oidc: OidcClient, tes_for):
    """No token, a non-JWT and an opaque token get 401 at a JWT-validating TES."""
    url = tes_for(issuer_url("a"))
    assert _create(url, None) == 401
    assert _create(url, "not-a-jwt") == 401
    assert _create(url, oidc.mint("alice", format="opaque")["access_token"]) == 401
    assert _create(url, oidc.mint("alice")["access_token"]) == 200


def test_no_issuer_or_unreachable_issuer(oidc: OidcClient, tes_for):
    """Without pinned issuers, or with an unreachable one, every token gets 401."""
    token = oidc.mint("alice")["access_token"]
    assert _create(tes_for(), token) == 401
    down = "http://127.0.0.1:9/a"
    assert _create(tes_for(down), oidc.mint("alice", claims={"iss": down})["access_token"]) == 401


def test_rotation_refetches_jwks(oidc: OidcClient, tes_for):
    """After a rotation without overlap, tokens with the new key are accepted (JWKS refetch)."""
    url = tes_for(issuer_url("a"))
    assert _create(url, oidc.mint("alice")["access_token"]) == 200
    oidc.rotate("a", keep_previous=False)
    assert _create(url, oidc.mint("alice")["access_token"]) == 200


def test_userinfo_wrong_content_type_refused(oidc: OidcClient, tes_for):
    """Userinfo answers that are not ``application/json`` give 401."""
    url = tes_for(issuer_url("a"), userinfo=True)
    oidc.userinfo_behaviour({"content_type": "text/plain"})
    assert _create(url, oidc.mint("alice")["access_token"]) == 401


def test_userinfo_cache_ttl_and_size(oidc: OidcClient, tes_for, monkeypatch):
    """Cached answers expire after the TTL, and the cache keeps at most its size (LRU)."""
    monkeypatch.setattr(server, "USERINFO_TTL", 2.0)
    monkeypatch.setattr(server, "USERINFO_CACHE_SIZE", 1)
    url = tes_for(issuer_url("a"), userinfo=True)
    first, second = (oidc.mint(sub)["access_token"] for sub in ("alice", "bob"))
    assert _create(url, first) == 200 and _create(url, first) == 200
    assert len(oidc.userinfo_calls()) == 1
    time.sleep(2.2)
    assert _create(url, first) == 200
    assert len(oidc.userinfo_calls()) == 2
    assert _create(url, second) == 200 and _create(url, first) == 200
    assert [c["sub"] for c in oidc.userinfo_calls()] == ["alice", "alice", "bob", "alice"]


def test_userinfo_cache_ends_with_token(oidc: OidcClient):
    """A cache entry lasts at most until the token's ``exp``: past it, userinfo is fetched again."""
    auth = server.OidcAuth(server.Settings(issuers=(issuer_url("a"),), audience=AUDIENCE, userinfo=True))
    token = oidc.mint("alice")["access_token"]
    claims = {"sub": "alice", "exp": time.time() - 1}
    assert auth._userinfo(issuer_url("a"), token, claims)["sub"] == "alice"
    assert auth._userinfo(issuer_url("a"), token, claims)["sub"] == "alice"
    assert len(oidc.userinfo_calls()) == 2
    claims["exp"] = time.time() + 3600
    auth._userinfo(issuer_url("a"), token, claims)
    auth._userinfo(issuer_url("a"), token, claims)
    assert len(oidc.userinfo_calls()) == 3


def test_multi_issuer_owners(oidc: OidcClient, stub: StubClient, tes_for):
    """Pinned to two issuers, the same ``sub`` from each is a different owner ``<iss>|<sub>``."""
    stub.script(default=ALLOW)
    url = tes_for(issuer_url("a"), issuer_url("b"), pdp=STUB.host_url)
    from_a = oidc.mint("alice", issuer="a")["access_token"]
    from_b = oidc.mint("alice", issuer="b")["access_token"]
    assert _create(url, from_a) == 200 and _create(url, from_b) == 200
    assert [r["body"]["subject"]["id"] for r in stub.requests()] == [
        f"{issuer_url('a')}|alice",
        f"{issuer_url('b')}|alice",
    ]
    builtin = tes_for(issuer_url("a"), issuer_url("b"))
    status, body = http("POST", builtin + "/tasks", TASK, {"Authorization": "Bearer " + from_a})
    assert status == 200
    assert http("GET", f"{builtin}/tasks/{body['id']}", None, {"Authorization": "Bearer " + from_b})[0] == 404
    assert http("GET", f"{builtin}/tasks/{body['id']}", None, {"Authorization": "Bearer " + from_a})[0] == 200

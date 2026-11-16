"""Tests of the mock OIDC issuer itself.

Most run against an in-process issuer (no containers); the last ones check
the compose service ``tes-authz-oidc`` from the host.
"""

from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
import urllib.error
import urllib.request

import jwt
import pytest

from harness.oidc import AUDIENCE, HOST_BASE, OIDC, OidcClient, default_claims, issuer_url
from harness.tes import Identity
from issuer import make_server
from minijose import decode_unverified, verify_jwt

from .conftest import http


@pytest.fixture(scope="module")
def local():
    """An in-process issuer on a free loopback port, with its client."""
    server, state = make_server(0, ["a", "b"], host="127.0.0.1")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    yield base, OidcClient(base), state
    server.shutdown()
    server.server_close()


@pytest.fixture
def issuer(local):
    """The in-process issuer, reset: (base URL, client)."""
    base, client, _ = local
    client.reset()
    return base, client


def _userinfo(base, token, name="a", method="GET"):
    request = urllib.request.Request(f"{base}/{name}/userinfo", method=method, data=b"" if method == "POST" else None)
    if token is not None:
        request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.headers.get("Content-Type"), response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type"), exc.read().decode()


def test_discovery_follows_host(issuer):
    """Discovery names the issuer and endpoints under the host name used."""
    base, _ = issuer
    status, doc = http("GET", f"{base}/a/.well-known/openid-configuration")
    assert status == 200 and doc["issuer"] == f"{base}/a"
    assert doc["jwks_uri"] == f"{base}/a/jwks" and doc["userinfo_endpoint"] == f"{base}/a/userinfo"
    port = base.rsplit(":", 1)[1]
    status, doc = http("GET", f"{base}/b/.well-known/openid-configuration", headers={"Host": f"tes-authz-oidc:{port}"})
    assert doc["issuer"] == f"http://tes-authz-oidc:{port}/b"
    assert http("GET", f"{base}/c/.well-known/openid-configuration")[0] == 404


def test_jwt_validates_with_published_jwks(issuer):
    """A minted JWT carries the requested claims and verifies with the JWKS (PyJWT and ours)."""
    base, client = issuer
    answer = client.mint("alice", base=base, scope="openid x", claims={"eduperson_entitlement": ["g"]})
    token = answer["access_token"]
    jwks = client.jwks("a")
    claims = verify_jwt(token, jwks, f"{base}/a", AUDIENCE)
    assert claims["sub"] == "alice" and claims["scope"] == "openid x" and claims["eduperson_entitlement"] == ["g"]
    assert claims["exp"] - claims["iat"] == 3600
    client_jwks = jwt.PyJWKClient(f"{base}/a/jwks")
    key = client_jwks.get_signing_key_from_jwt(token).key
    assert jwt.decode(token, key, algorithms=["RS256"], audience=AUDIENCE, issuer=f"{base}/a")["sub"] == "alice"


def test_base_defaults_to_control_host(issuer):
    """Without ``base``, ``iss`` uses the control request's host."""
    base, client = issuer
    assert client.mint("alice")["iss"] == f"{base}/a"
    assert client.mint("alice", base="http://tes-authz-oidc:8080", issuer="b")["iss"] == "http://tes-authz-oidc:8080/b"


def test_claim_overrides(issuer):
    """``aud``, ``expires_in`` and ``claims`` override the defaults, also ``iss``."""
    base, client = issuer
    token = client.mint(
        "alice", base=base, aud=["tes-authz", "other"], expires_in=-10, claims={"iss": "http://evil/a", "x": 1}
    )["access_token"]
    _, claims = decode_unverified(token)
    assert claims["aud"] == ["tes-authz", "other"] and claims["exp"] < time.time()
    assert claims["iss"] == "http://evil/a" and claims["x"] == 1


def test_issuers_have_separate_keys(issuer):
    """Issuers ``a`` and ``b`` sign with different keys; a token of one fails with the other's JWKS."""
    base, client = issuer
    assert {k["kid"] for k in client.jwks("a")["keys"]}.isdisjoint(k["kid"] for k in client.jwks("b")["keys"])
    token = client.mint("alice", base=base, issuer="b")["access_token"]
    with pytest.raises(ValueError, match="signing key"):
        verify_jwt(token, client.jwks("a"), f"{base}/b", AUDIENCE)
    assert verify_jwt(token, client.jwks("b"), f"{base}/b", AUDIENCE)["iss"] == f"{base}/b"


def test_opaque_token_validated_at_userinfo(issuer):
    """Opaque tokens are not JWTs; userinfo returns ``sub`` plus the scripted claims."""
    base, client = issuer
    token = client.mint("alice", base=base, format="opaque", userinfo={"eduperson_entitlement": ["g"]})["access_token"]
    assert token.count(".") == 0
    status, content_type, body = _userinfo(base, token)
    assert status == 200 and content_type == "application/json"
    assert json.loads(body) == {"sub": "alice", "eduperson_entitlement": ["g"]}
    assert _userinfo(base, token, method="POST")[0] == 200


@pytest.mark.parametrize("fmt", ["jwt", "opaque"])
def test_userinfo_refuses_bad_tokens(issuer, fmt):
    """Unknown, missing, expired and other-issuer tokens get 401 at userinfo."""
    base, client = issuer
    expired = client.mint("alice", base=base, format=fmt, expires_in=-1)["access_token"]
    good = client.mint("alice", base=base, format=fmt)["access_token"]
    for token, name in ((None, "a"), ("nope", "a"), (expired, "a"), (good, "b")):
        status, _, _ = _userinfo(base, token, name)
        assert status == 401


def test_userinfo_jwt_mode(issuer):
    """JWT mode answers ``application/jwt`` (TESes must refuse it, spec section 3.6)."""
    base, client = issuer
    token = client.mint("alice", base=base)["access_token"]
    client.userinfo_behaviour({"mode": "jwt"})
    status, content_type, body = _userinfo(base, token)
    assert status == 200 and content_type == "application/jwt"
    claims = verify_jwt(body, client.jwks("a"), f"{base}/a", AUDIENCE)
    assert claims["sub"] == "alice"


def test_userinfo_failures_and_mismatch(issuer):
    """Scripted status, ``sub`` mismatch, delay and a dropped connection."""
    base, client = issuer
    alice = client.mint("alice", base=base)["access_token"]
    bob = client.mint("bob", base=base)["access_token"]
    client.userinfo_behaviour({"status": 503}, {"bob": {"sub": "mallory"}})
    assert _userinfo(base, alice)[0] == 503
    status, _, body = _userinfo(base, bob)
    assert status == 200 and json.loads(body)["sub"] == "mallory"
    client.userinfo_behaviour({"delay": 0.3, "content_type": "text/plain"})
    started = time.monotonic()
    status, content_type, _ = _userinfo(base, alice)
    assert status == 200 and content_type == "text/plain" and time.monotonic() - started >= 0.3
    client.userinfo_behaviour({"close": True})
    with pytest.raises((urllib.error.URLError, ConnectionError, socket.timeout)):
        urllib.request.urlopen(
            urllib.request.Request(f"{base}/a/userinfo", headers={"Authorization": "Bearer " + alice}), timeout=5
        )


def test_userinfo_calls_recorded_without_token(issuer):
    """Calls are recorded with a token hash, never the token."""
    base, client = issuer
    token = client.mint("alice", base=base)["access_token"]
    _userinfo(base, token)
    _userinfo(base, "nope")
    calls = client.userinfo_calls()
    assert [(c["sub"], c["status"]) for c in calls] == [("alice", 200), (None, 401)]
    assert calls[0]["token_sha256"] == hashlib.sha256(token.encode()).hexdigest()[:16]
    assert token not in str(calls)
    client.reset()
    assert client.userinfo_calls() == []
    assert _userinfo(base, token)[0] == 401


def test_key_rotation(issuer):
    """Rotation with overlap keeps old tokens valid; without overlap, or after retiring, they fail."""
    base, client = issuer
    old = client.mint("alice", base=base)["access_token"]
    old_kid = decode_unverified(old)[0]["kid"]
    new_kid = client.rotate("a", keep_previous=True)
    new = client.mint("alice", base=base)["access_token"]
    assert decode_unverified(new)[0]["kid"] == new_kid
    for token in (old, new):
        assert verify_jwt(token, client.jwks("a"), f"{base}/a", AUDIENCE)
    client.retire(old_kid, "a")
    with pytest.raises(ValueError, match="signing key"):
        verify_jwt(old, client.jwks("a"), f"{base}/a", AUDIENCE)
    newest = client.rotate("a", keep_previous=False)
    assert [k["kid"] for k in client.jwks("a")["keys"]] == [newest]
    with pytest.raises(urllib.error.HTTPError) as exc:
        client.retire(newest, "a")
    assert exc.value.code == 400
    retired_signed = client.mint("alice", base=base, key=old_kid)["access_token"]
    assert decode_unverified(retired_signed)[0]["kid"] == old_kid


def test_unpublished_key_and_alg_none(issuer):
    """``key: unpublished`` signs with a key never in the JWKS; ``alg: none`` is unsigned."""
    base, client = issuer
    rogue = client.mint("alice", base=base, key="unpublished")
    assert rogue["kid"] not in {k["kid"] for k in client.jwks("a")["keys"]}
    unsigned = client.mint("alice", base=base, alg="none")["access_token"]
    assert decode_unverified(unsigned)[0]["alg"] == "none" and unsigned.endswith(".")


def test_reset_keys(issuer):
    """``reset(keys=True)`` replaces every issuer's keys."""
    _, client = issuer
    before = client.jwks("a")
    client.reset(keys=True)
    assert client.jwks("a") != before


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"sub": ""},
        {"sub": "a", "issuer": "z"},
        {"sub": "a", "base": "http://h/path"},
        {"sub": "a", "format": "saml"},
        {"sub": "a", "expires_in": "1"},
        {"sub": "a", "claims": []},
        {"sub": "a", "alg": "HS256"},
        {"sub": "a", "key": "no-such-kid"},
        [],
    ],
)
def test_control_validation(issuer, body):
    """Malformed control requests get 400."""
    base, _ = issuer
    assert http("POST", f"{base}/_control/tokens", body)[0] == 400


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("PUT", "/_control/userinfo", {"default": {"mode": "xml"}}),
        ("PUT", "/_control/userinfo", {"subjects": {"a": 1}}),
        ("PUT", "/_control/userinfo", {"default": {"status": "x"}}),
        ("PUT", "/_control/userinfo", {"default": {"status": 99}}),
        ("PUT", "/_control/userinfo", {"default": {"delay": -1}}),
        ("PUT", "/_control/userinfo", {"default": {"delay": "1"}}),
        ("PUT", "/_control/userinfo", {"default": {"close": "yes"}}),
        ("PUT", "/_control/userinfo", {"subjects": {"a": {"sub": 1}}}),
        ("PUT", "/_control/userinfo", []),
        ("POST", "/_control/keys/rotate", {"issuer": "z"}),
        ("POST", "/_control/keys/retire", {"kid": "nope"}),
    ],
)
def test_control_validation_other(issuer, method, path, body):
    """Malformed behaviour and key requests get 400."""
    base, _ = issuer
    assert http(method, base + path, body)[0] == 400


def test_token_endpoint_and_unknown_paths(issuer):
    """The token endpoint refuses every grant; unknown paths are 404."""
    base, _ = issuer
    status, body = http("POST", f"{base}/a/token", {})
    assert status == 400 and body["error"] == "unsupported_grant_type"
    for method, path in (("GET", "/x"), ("GET", "/a/x"), ("POST", "/a/x"), ("POST", "/_control/x"), ("PUT", "/x")):
        assert http(method, base + path, {} if method != "GET" else None)[0] == 404


def test_issuer_names_checked():
    """Issuer names must be distinct path segments."""
    for names in ([], ["a", "a"], ["A"], ["a/b"]):
        with pytest.raises(ValueError, match="issuer names"):
            make_server(0, names, host="127.0.0.1")


def test_token_for_identities(issuer):
    """``token_for`` caches per identity and options and fills userinfo per format."""
    base, client = issuer
    alice = Identity("alice", {"scope": "openid", "e": ["t"]}, {"e": ["u"], "only": 1})
    first = client.token_for(alice, base=base)
    assert client.token_for(alice, base=base) == first
    assert client.token_for(alice, base=base, issuer="b") != first
    _, claims = decode_unverified(first)
    assert claims["azp"] == "tes-client" and claims["e"] == ["t"]
    assert json.loads(_userinfo(base, first)[2]) == {"sub": "alice", "e": ["u"], "only": 1}
    opaque = client.token_for(alice, base=base, fmt="opaque")
    info = json.loads(_userinfo(base, opaque)[2])
    assert info["e"] == ["t"] and info["only"] == 1 and info["azp"] == "tes-client"
    service = Identity("protes", {"scope": "openid"}, client_credentials=True)
    assert default_claims(service) == {"scope": "openid", "client_id": "protes"}
    client.reset()
    assert client.token_for(alice, base=base) != first


@pytest.mark.services
def test_compose_issuer(oidc):
    """The compose issuer answers on the host port with the host issuer URL."""
    status, doc = http("GET", issuer_url("a") + "/.well-known/openid-configuration")
    assert status == 200 and doc["issuer"] == issuer_url("a") == f"{HOST_BASE}/a"
    token = OIDC.token_for(Identity("alice"))
    assert verify_jwt(token, oidc.jwks("a"), issuer_url("a"), AUDIENCE)["sub"] == "alice"
    network = OIDC.mint("alice", base="http://tes-authz-oidc:8080")
    assert network["iss"] == "http://tes-authz-oidc:8080/a"

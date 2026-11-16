"""Unit tests of the mock issuer's JOSE module, cross-checked with PyJWT.

PyJWT with ``cryptography`` stands in for the TESes' JOSE stacks (Spring
Security/Nimbus in TESK, go-jose in Funnel, python-jose in TESP): if it
accepts our tokens and we accept its tokens, the RS256 encoding is standard.
"""

from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from minijose import (
    JoseError,
    UnknownKeyError,
    b64url_decode,
    b64url_encode,
    decode_unverified,
    encode_jwt,
    generate_rsa_key,
    public_key_from_jwk,
    rs256_sign,
    rs256_verify,
    verify_jwt,
)

ISS = "http://127.0.0.1:18193/a"
AUD = "tes-authz"


@pytest.fixture(scope="module")
def key():
    """One 2048-bit key for the module."""
    return generate_rsa_key(2048, kid="k1")


def _claims(**extra):
    now = int(time.time())
    return {"iss": ISS, "sub": "alice", "aud": AUD, "iat": now, "exp": now + 60, **extra}


def test_key_shape(key):
    """Keys have the requested size and a JWK with the RS256 fields."""
    assert key.n.bit_length() == 2048
    jwk = key.public_jwk()
    assert jwk["kty"] == "RSA" and jwk["alg"] == "RS256" and jwk["use"] == "sig" and jwk["kid"] == "k1"
    assert public_key_from_jwk(jwk).n == key.n


@pytest.mark.parametrize("bits", [512, 1023, 2047])
def test_key_size_checked(bits):
    """Too small or odd key sizes are refused."""
    with pytest.raises(ValueError, match="bits"):
        generate_rsa_key(bits)


def test_pyjwt_accepts_our_tokens(key):
    """PyJWT verifies our RS256 tokens with our JWK."""
    token = encode_jwt(_claims(scope="openid"), key)
    public = jwt.PyJWK(key.public_jwk()).key
    claims = jwt.decode(token, public, algorithms=["RS256"], audience=AUD, issuer=ISS)
    assert claims["sub"] == "alice" and claims["scope"] == "openid"
    assert jwt.get_unverified_header(token)["kid"] == "k1"


def test_we_accept_pyjwt_tokens():
    """Our verifier accepts tokens signed by ``cryptography`` through PyJWT."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk["kid"] = "ext"
    token = jwt.encode(_claims(), private, algorithm="RS256", headers={"kid": "ext"})
    assert verify_jwt(token, {"keys": [jwk]}, ISS, AUD)["sub"] == "alice"


def test_sign_verify_roundtrip(key):
    """A signature verifies for its message only."""
    signature = rs256_sign(key, b"m")
    assert rs256_verify(key, b"m", signature)
    assert not rs256_verify(key, b"n", signature)
    assert not rs256_verify(key, b"m", signature[:-1])
    assert not rs256_verify(key, b"m", (key.n + 1).to_bytes(key.size + 1, "big")[1:])


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"iss": "http://other/a"}, "wrong issuer"),
        ({"aud": "other"}, "wrong audience"),
        ({"aud": ["x", "y"]}, "wrong audience"),
        ({"exp": int(time.time()) - 1}, "expired"),
        ({"exp": "9999999999"}, "expired"),
        ({"exp": True}, "expired"),
        ({"exp": float("inf")}, "expired"),
        ({"exp": float("nan")}, "expired"),
        ({"nbf": float("nan")}, "nbf is not a number"),
        ({"nbf": int(time.time()) + 600}, "not yet valid"),
        ({"iat": "now"}, "iat is not a number"),
        ({"sub": ""}, "no sub"),
        ({"sub": 7}, "no sub"),
    ],
)
def test_claim_checks(key, change, message):
    """Issuer, audience, expiry, not-before and subject are enforced."""
    token = encode_jwt({**_claims(), **change}, key)
    with pytest.raises(JoseError, match=message):
        verify_jwt(token, {"keys": [key.public_jwk()]}, ISS, AUD)


def test_audience_list_and_missing_exp(key):
    """An audience list containing ours passes; a token without ``exp`` fails."""
    jwks = {"keys": [key.public_jwk()]}
    assert verify_jwt(encode_jwt(_claims(aud=["x", AUD]), key), jwks, ISS, AUD)
    claims = _claims()
    del claims["exp"]
    with pytest.raises(JoseError, match="expired or no exp"):
        verify_jwt(encode_jwt(claims, key), jwks, ISS, AUD)


def test_alg_none_and_tampering_refused(key):
    """``alg: none``, other algorithms, a changed payload and foreign keys fail."""
    jwks = {"keys": [key.public_jwk()]}
    with pytest.raises(JoseError, match="alg"):
        verify_jwt(encode_jwt(_claims(), None, alg="none"), jwks, ISS, AUD)
    with pytest.raises(JoseError, match="alg"):
        verify_jwt(encode_jwt(_claims(), key, header={"alg": "HS256"}), jwks, ISS, AUD)
    head, _, sig = encode_jwt(_claims(), key).split(".")
    forged = head + "." + b64url_encode(json.dumps(_claims(sub="mallory")).encode()) + "." + sig
    with pytest.raises(JoseError, match="bad signature"):
        verify_jwt(forged, jwks, ISS, AUD)
    other = generate_rsa_key(2048, kid="k1")
    with pytest.raises(JoseError, match="bad signature"):
        verify_jwt(encode_jwt(_claims(), other), jwks, ISS, AUD)


def test_key_selection(key):
    """The ``kid`` selects the key; an unknown ``kid`` or an ambiguous JWKS fails."""
    other = generate_rsa_key(2048, kid="k2")
    both = {"keys": [key.public_jwk(), other.public_jwk()]}
    assert verify_jwt(encode_jwt(_claims(), other), both, ISS, AUD)
    with pytest.raises(UnknownKeyError):
        verify_jwt(encode_jwt(_claims(), key), {"keys": [other.public_jwk()]}, ISS, AUD)
    no_kid = encode_jwt(_claims(), key, header={"kid": None})
    assert verify_jwt(no_kid, {"keys": [key.public_jwk()]}, ISS, AUD)
    with pytest.raises(UnknownKeyError):
        verify_jwt(no_kid, both, ISS, AUD)
    for token in (encode_jwt(_claims(aud="other"), key), encode_jwt(_claims(), other, header={"kid": "k1"})):
        with pytest.raises(JoseError) as failure:
            verify_jwt(token, both, ISS, AUD)
        assert not isinstance(failure.value, UnknownKeyError)


@pytest.mark.parametrize("token", ["", "a.b", "a.b.c.d", "!!.e30.x", "e30.W10.x", 7])
def test_malformed_tokens(token):
    """Tokens that are not compact JWS with JSON objects are refused."""
    with pytest.raises(JoseError):
        decode_unverified(token)


@pytest.mark.parametrize("jwk", [{"kty": "EC"}, {"kty": "RSA"}, {"kty": "RSA", "n": "AQAB", "e": "AQAB"}, []])
def test_bad_jwks(jwk):
    """Non-RSA, incomplete and weak JWKs are refused."""
    with pytest.raises(JoseError):
        public_key_from_jwk(jwk)


def test_b64url():
    """Base64url is unpadded and strict about the alphabet."""
    assert b64url_encode(b"\xfb\xff") == "-_8"
    assert b64url_decode("-_8") == b"\xfb\xff"
    for bad in ("+/8", "AA==", None):
        with pytest.raises(JoseError):
            b64url_decode(bad)

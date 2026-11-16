"""Minimal JOSE for the mock OIDC issuer: RSA keys, JWKS, RS256 JWTs.

Standard library only, like the shims, so the issuer container needs
nothing but a Python image. Test-only: key generation and signing are
textbook RSA (PKCS #1 v1.5 signatures, RFC 8017) without side-channel
hardening. Never use it for real keys.

Interoperability with real JOSE stacks (PyJWT with ``cryptography``,
and through them the Java, Go and Python stacks of the TESes) is pinned by
``tests/test_oidc_jose.py``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
import time
from dataclasses import dataclass
from typing import Any, TypeGuard

PUBLIC_EXPONENT = 65537
"""RSA public exponent."""

SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
"""DER prefix of the ``DigestInfo`` for SHA-256 (RFC 8017, section 9.2)."""

_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % d for d in range(3, math.isqrt(p) + 1, 2))]


class JoseError(ValueError):
    """Raised when a token is malformed or fails validation."""


class UnknownKeyError(JoseError):
    """Raised when the token's signing key is not (or not unambiguously) in the JWKS."""


def b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url.

    Args:
        data: The bytes.

    Returns:
        The text.
    """
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url.

    Args:
        text: The text.

    Returns:
        The bytes.

    Raises:
        JoseError: If the text is not base64url.
    """
    if not isinstance(text, str) or any(c in text for c in "+/="):
        raise JoseError("not base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise JoseError("not base64url") from exc


def _int_to_bytes(value: int, length: int | None = None) -> bytes:
    size = length if length is not None else max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(size, "big")


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin test with random bases.

    Args:
        n: The candidate (odd, > 3).
        rounds: Number of rounds.

    Returns:
        Whether ``n`` is probably prime.
    """
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits: int) -> int:
    """Return a random prime of exactly ``bits`` bits with the top two bits set.

    Args:
        bits: The size in bits.

    Returns:
        The prime.
    """
    while True:
        candidate = secrets.randbits(bits) | (3 << (bits - 2)) | 1
        if math.gcd(candidate - 1, PUBLIC_EXPONENT) == 1 and _is_probable_prime(candidate):
            return candidate


@dataclass(frozen=True)
class RsaKey:
    """An RSA key pair with its key ID.

    Attributes:
        kid: The JWK key ID.
        n: The modulus.
        e: The public exponent.
        d: The private exponent.
    """

    kid: str
    n: int
    e: int
    d: int

    @property
    def size(self) -> int:
        """The modulus length in bytes."""
        return (self.n.bit_length() + 7) // 8

    def public_jwk(self) -> dict[str, str]:
        """Return the public key as a JWK (RFC 7517, RFC 7518 section 6.3).

        Returns:
            The JWK.
        """
        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": b64url_encode(_int_to_bytes(self.n)),
            "e": b64url_encode(_int_to_bytes(self.e)),
        }


def generate_rsa_key(bits: int = 2048, kid: str | None = None) -> RsaKey:
    """Generate an RSA key pair.

    Args:
        bits: Modulus size in bits (even, at least 1024).
        kid: Key ID (default: random).

    Returns:
        The key.

    Raises:
        ValueError: If ``bits`` is too small or odd.
    """
    if bits < 1024 or bits % 2:
        raise ValueError("bits must be even and at least 1024")
    while True:
        p, q = _random_prime(bits // 2), _random_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        lam = math.lcm(p - 1, q - 1)
        d = pow(PUBLIC_EXPONENT, -1, lam)
        return RsaKey(kid or secrets.token_hex(8), n, PUBLIC_EXPONENT, d)


def public_key_from_jwk(jwk: dict[str, Any]) -> RsaKey:
    """Read a public RSA JWK.

    Args:
        jwk: The JWK.

    Returns:
        A key without private exponent (``d == 0``).

    Raises:
        JoseError: If the JWK is not a usable RSA key.
    """
    if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
        raise JoseError("not an RSA JWK")
    try:
        n = int.from_bytes(b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(b64url_decode(jwk["e"]), "big")
    except (KeyError, TypeError) as exc:
        raise JoseError("RSA JWK without n or e") from exc
    if n.bit_length() < 1024 or e < 3:
        raise JoseError("RSA JWK too weak")
    return RsaKey(str(jwk.get("kid", "")), n, e, 0)


def _emsa_pkcs1_v15(message: bytes, size: int) -> bytes:
    """Encode a message for an RS256 signature (RFC 8017, section 9.2).

    Args:
        message: The signing input.
        size: The modulus length in bytes.

    Returns:
        The encoded message.
    """
    t = SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    return b"\x00\x01" + b"\xff" * (size - len(t) - 3) + b"\x00" + t


def rs256_sign(key: RsaKey, message: bytes) -> bytes:
    """Sign with RSASSA-PKCS1-v1_5 and SHA-256.

    Args:
        key: The private key.
        message: The signing input.

    Returns:
        The signature.
    """
    m = int.from_bytes(_emsa_pkcs1_v15(message, key.size), "big")
    return _int_to_bytes(pow(m, key.d, key.n), key.size)


def rs256_verify(key: RsaKey, message: bytes, signature: bytes) -> bool:
    """Verify an RSASSA-PKCS1-v1_5 SHA-256 signature.

    Args:
        key: The public key.
        message: The signing input.
        signature: The signature.

    Returns:
        Whether the signature is valid.
    """
    if len(signature) != key.size:
        return False
    s = int.from_bytes(signature, "big")
    if s >= key.n:
        return False
    return hmac.compare_digest(_int_to_bytes(pow(s, key.e, key.n), key.size), _emsa_pkcs1_v15(message, key.size))


def encode_jwt(
    claims: dict[str, Any], key: RsaKey | None, alg: str = "RS256", header: dict[str, Any] | None = None
) -> str:
    """Encode and sign a JWT.

    Args:
        claims: The payload.
        key: The signing key (ignored for ``alg="none"``).
        alg: ``RS256`` or ``none`` (the latter only to test that TESes refuse it).
        header: Extra or overriding header fields.

    Returns:
        The compact JWS.

    Raises:
        ValueError: For an unsupported algorithm or a missing key.
    """
    head: dict[str, Any] = {"alg": alg, "typ": "JWT"}
    if alg == "RS256":
        if key is None:
            raise ValueError("RS256 needs a key")
        head["kid"] = key.kid
    elif alg != "none":
        raise ValueError(f"unsupported alg {alg}")
    head.update(header or {})
    signing_input = (
        b64url_encode(json.dumps(head, separators=(",", ":")).encode())
        + "."
        + b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    )
    signature = rs256_sign(key, signing_input.encode("ascii")) if alg == "RS256" and key is not None else b""
    return signing_input + "." + b64url_encode(signature)


def decode_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Split a compact JWS without checking anything but its shape.

    Args:
        token: The token.

    Returns:
        Header and payload.

    Raises:
        JoseError: If the token is not a compact JWS with JSON objects.
    """
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        raise JoseError("not a compact JWS")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except ValueError as exc:
        raise JoseError("JWS parts are not JSON") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JoseError("JWS parts are not JSON objects")
    return header, payload


def _is_number(value: Any) -> TypeGuard[int | float]:
    """Tell whether a claim is a finite JSON number (not a boolean, NaN or infinity)."""
    return isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value)


def verify_jwt(
    token: str, jwks: dict[str, Any], issuer: str, audience: str, now: float | None = None, leeway: float = 0
) -> dict[str, Any]:
    """Validate an RS256 access token as a resource server does.

    Checks: ``alg`` is ``RS256``; the ``kid`` (or the only key) is in the
    JWKS; the signature; ``iss`` equals ``issuer``; ``aud`` (string or
    list) contains ``audience``; ``exp`` is a number in the future; ``nbf``
    and ``iat``, if present, are numbers and ``nbf`` has passed.

    Args:
        token: The compact JWS.
        jwks: The issuer's JWK Set.
        issuer: The pinned issuer.
        audience: The expected audience.
        now: The current time (default: ``time.time()``).
        leeway: Seconds of clock skew allowed.

    Returns:
        The validated claims.

    Raises:
        JoseError: If any check fails.
    """
    header, claims = decode_unverified(token)
    if header.get("alg") != "RS256":
        raise JoseError("alg must be RS256")
    keys = [k for k in jwks.get("keys", []) if isinstance(k, dict)] if isinstance(jwks, dict) else []
    kid = header.get("kid")
    candidates = [k for k in keys if k.get("kid") == kid] if kid is not None else keys
    if len(candidates) != 1:
        raise UnknownKeyError("signing key not in JWKS")
    signing_input, _, signature = token.rpartition(".")
    if not rs256_verify(public_key_from_jwk(candidates[0]), signing_input.encode("ascii"), b64url_decode(signature)):
        raise JoseError("bad signature")
    current = time.time() if now is None else now
    if claims.get("iss") != issuer:
        raise JoseError("wrong issuer")
    aud = claims.get("aud")
    if not (aud == audience or (isinstance(aud, list) and audience in aud)):
        raise JoseError("wrong audience")
    exp = claims.get("exp")
    if not _is_number(exp) or exp + leeway <= current:
        raise JoseError("expired or no exp")
    for name in ("nbf", "iat"):
        if name in claims and not _is_number(claims[name]):
            raise JoseError(f"{name} is not a number")
    if "nbf" in claims and claims["nbf"] - leeway > current:
        raise JoseError("not yet valid")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise JoseError("no sub")
    return claims

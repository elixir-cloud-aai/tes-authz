"""Mock OIDC issuer for the TES AuthZ harness (test-only).

One process serves several issuers (default ``a`` and ``b``, for
multi-issuer cases with ``<iss>|<sub>`` owners), each under its own path.
The issuer URL is ``http://<Host header>/<name>``, so the same issuer is
consistent for a TES on the host (``http://127.0.0.1:18193/a``) and for one
on the compose network (``http://tes-authz-oidc:8080/a``): discovery
returns the issuer and endpoint URLs for the host name the TES used.
Tokens carry the ``iss`` the test asked for (see ``base`` below).

Issuer endpoints (``<n>`` = issuer name):
    GET      /<n>/.well-known/openid-configuration   discovery
    GET      /<n>/jwks                               JWK Set (published keys)
    GET|POST /<n>/userinfo                           userinfo (Bearer token)
    POST     /<n>/token                              always 400 (tokens come from the control API)
    GET      /health

Control endpoints (tests and adapters only; a TES never calls them):
    POST /_control/tokens          mint a token, see ``mint`` below
    POST /_control/keys/rotate     {"issuer", "keep_previous": true} -> new active key
    POST /_control/keys/retire     {"issuer", "kid"} -> drop a key from the JWKS
    PUT  /_control/userinfo        {"default": <behaviour>, "subjects": {<sub>: <behaviour>}}
    GET  /_control/userinfo-calls  recorded userinfo calls, oldest first
    POST /_control/reset           {"keys": false} -> forget tokens, behaviours, calls (and keys)

Token request (``POST /_control/tokens``)::

    {"sub": "alice", "issuer": "a", "base": "http://tes-authz-oidc:8080",
     "format": "jwt" | "opaque", "aud": "tes-authz" | [...], "scope": "openid ...",
     "expires_in": 3600, "claims": {...}, "userinfo": {...},
     "key": "active" | "<kid>" | "unpublished", "alg": "RS256" | "none", "header": {...}}

Only ``sub`` is required. ``base`` defaults to the control request's own
host. ``claims`` are merged last into the JWT payload, so they can override
``iss``, ``aud``, ``exp`` or ``iat``. ``userinfo`` is what the userinfo
endpoint returns besides ``sub`` (for opaque tokens the only claims a TES
sees). Opaque tokens are random strings that only the userinfo endpoint
validates, as TESK does. Every minted token, JWT or opaque, works at
userinfo until it expires or the issuer is reset.

Userinfo behaviour (per subject, else the default)::

    {"mode": "json" | "jwt", "status": 200, "delay": 0, "close": false,
     "sub": "<override>", "content_type": "<override>"}

``mode: jwt`` answers with a signed ``application/jwt`` body, which a TES
must refuse (spec section 3.6); ``sub`` makes userinfo return another
subject (the TES must answer 401); ``status`` other than 200 returns an
error body; ``delay`` sleeps before answering; ``close`` drops the
connection without an answer.

Settings (environment): OIDC_PORT (default 8080), OIDC_ISSUERS (default
``a,b``), OIDC_KEY_BITS (default 2048), OIDC_DEFAULT_AUDIENCE (default
``tes-authz``), OIDC_MAX_TOKENS (default 100000), OIDC_LOG_LEVEL (default
INFO).
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from minijose import RsaKey, encode_jwt, generate_rsa_key

DEFAULT_AUDIENCE = os.environ.get("OIDC_DEFAULT_AUDIENCE", "tes-authz")
"""Audience of minted tokens unless the request names one."""

MAX_TOKENS = int(os.environ.get("OIDC_MAX_TOKENS", "100000"))
"""Most tokens remembered for userinfo; the oldest are forgotten first."""

MAX_BODY_BYTES = 1024 * 1024
"""Largest control request body."""

NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
"""Allowed issuer names (one path segment)."""

DEFAULT_BEHAVIOUR: dict[str, Any] = {"mode": "json", "status": 200}

log = logging.getLogger("tes-authz-oidc")


class ControlError(ValueError):
    """A control request that cannot be served (answered with 400)."""


@dataclass
class TokenRecord:
    """What the issuer remembers about a minted token.

    Attributes:
        issuer: Issuer name.
        sub: Subject.
        exp: Expiry (seconds since the epoch).
        userinfo: Claims userinfo returns besides ``sub``.
    """

    issuer: str
    sub: str
    exp: float
    userinfo: dict[str, Any]


@dataclass
class IssuerKeys:
    """Signing keys of one issuer.

    Attributes:
        published: Keys in the JWKS, by key ID.
        active: Key ID used for signing by default.
        retired: Keys removed from the JWKS (still usable via ``key``).
        unpublished: A key that never appears in the JWKS, made on first use.
    """

    published: dict[str, RsaKey]
    active: str
    retired: dict[str, RsaKey] = field(default_factory=dict)
    unpublished: RsaKey | None = None


class State:
    """Issuers, tokens, behaviours and recorded calls, shared by all threads."""

    def __init__(self, names: list[str], key_bits: int = 2048) -> None:
        """Create the issuers with one fresh key each.

        Args:
            names: Issuer names (path segments).
            key_bits: RSA modulus size.

        Raises:
            ValueError: If a name is not a valid path segment or repeats.
        """
        if not names or len(set(names)) != len(names) or not all(NAME_PATTERN.match(n) for n in names):
            raise ValueError(f"bad issuer names {names!r}")
        self.lock = threading.Lock()
        self.key_bits = key_bits
        self.issuers: dict[str, IssuerKeys] = {name: self._new_keys() for name in names}
        self.tokens: OrderedDict[str, TokenRecord] = OrderedDict()
        self.behaviour: dict[str, Any] = {"default": dict(DEFAULT_BEHAVIOUR), "subjects": {}}
        self.calls: list[dict[str, Any]] = []

    def _new_keys(self) -> IssuerKeys:
        key = generate_rsa_key(self.key_bits)
        return IssuerKeys({key.kid: key}, key.kid)

    def reset(self, keys: bool = False) -> None:
        """Forget tokens, behaviours and calls, and optionally renew all keys.

        Args:
            keys: Also replace every issuer's keys with one fresh key.
        """
        fresh = {name: self._new_keys() for name in self.issuers} if keys else None
        with self.lock:
            self.tokens.clear()
            self.behaviour = {"default": dict(DEFAULT_BEHAVIOUR), "subjects": {}}
            self.calls = []
            if fresh is not None:
                self.issuers = fresh

    def jwks(self, name: str) -> dict[str, Any]:
        """Return an issuer's JWK Set.

        Args:
            name: Issuer name.

        Returns:
            The JWK Set.
        """
        with self.lock:
            return {"keys": [k.public_jwk() for k in self.issuers[name].published.values()]}

    def rotate(self, name: str, keep_previous: bool) -> str:
        """Make a new active key.

        Args:
            name: Issuer name.
            keep_previous: Keep the old keys in the JWKS (overlap), else retire them.

        Returns:
            The new key ID.
        """
        key = generate_rsa_key(self.key_bits)
        with self.lock:
            keys = self.issuers[name]
            if not keep_previous:
                keys.retired.update(keys.published)
                keys.published = {}
            keys.published[key.kid] = key
            keys.active = key.kid
        return key.kid

    def retire(self, name: str, kid: str) -> None:
        """Remove a key from the JWKS (tokens it signed then fail validation).

        Args:
            name: Issuer name.
            kid: Key ID.

        Raises:
            ControlError: If the key is not published or is the only one.
        """
        with self.lock:
            keys = self.issuers[name]
            if kid not in keys.published:
                raise ControlError("key not published")
            if len(keys.published) == 1:
                raise ControlError("cannot retire the only published key; rotate first")
            keys.retired[kid] = keys.published.pop(kid)
            if keys.active == kid:
                keys.active = next(iter(keys.published))

    def signing_key(self, name: str, choice: str) -> RsaKey:
        """Pick the key to sign with.

        Args:
            name: Issuer name.
            choice: ``active``, a key ID, or ``unpublished``.

        Returns:
            The key.

        Raises:
            ControlError: For an unknown key ID.
        """
        with self.lock:
            keys = self.issuers[name]
            if choice == "active":
                return keys.published[keys.active]
            if choice in keys.published:
                return keys.published[choice]
            if choice in keys.retired:
                return keys.retired[choice]
            if choice != "unpublished":
                raise ControlError("unknown key")
            if keys.unpublished is not None:
                return keys.unpublished
        key = generate_rsa_key(self.key_bits)
        with self.lock:
            if keys.unpublished is None:
                keys.unpublished = key
            return keys.unpublished

    def remember(self, token: str, record: TokenRecord) -> None:
        """Remember a token for userinfo.

        Args:
            token: The access token.
            record: What userinfo needs.
        """
        with self.lock:
            self.tokens[token] = record
            while len(self.tokens) > MAX_TOKENS:
                self.tokens.popitem(last=False)

    def lookup(self, token: str) -> TokenRecord | None:
        """Find a remembered token.

        Args:
            token: The access token.

        Returns:
            Its record, or ``None``.
        """
        with self.lock:
            return self.tokens.get(token)

    def behaviour_for(self, sub: str | None) -> dict[str, Any]:
        """Return the userinfo behaviour for a subject.

        Args:
            sub: The subject, if the token is known.

        Returns:
            The behaviour.
        """
        with self.lock:
            subjects = self.behaviour.get("subjects", {})
            chosen = subjects.get(sub) if sub is not None and sub in subjects else self.behaviour["default"]
            return {**DEFAULT_BEHAVIOUR, **copy.deepcopy(chosen)}

    def record_call(self, issuer: str, token: str | None, sub: str | None, status: int, mode: str) -> None:
        """Record one userinfo call (never the token itself).

        Args:
            issuer: Issuer name from the path.
            token: The presented token, if any.
            sub: The token's subject, if known.
            status: The answered status (0: connection dropped).
            mode: ``json`` or ``jwt``.
        """
        digest = hashlib.sha256(token.encode()).hexdigest()[:16] if token else None
        with self.lock:
            self.calls.append(
                {
                    "time": time.time(),
                    "issuer": issuer,
                    "sub": sub,
                    "token_sha256": digest,
                    "status": status,
                    "mode": mode,
                }
            )


def mint(state: State, request: Any, host_base: str) -> dict[str, Any]:
    """Mint a token as the control API asks.

    Args:
        state: The issuer state.
        request: The decoded control request.
        host_base: ``http://<Host>`` of the control request (default ``base``).

    Returns:
        ``{"access_token", "token_type", "expires_in", "iss", "kid"}``.

    Raises:
        ControlError: If the request is malformed.
    """
    if not isinstance(request, dict):
        raise ControlError("request must be a JSON object")
    sub = request.get("sub")
    name = request.get("issuer", next(iter(state.issuers)))
    if not isinstance(sub, str) or not sub:
        raise ControlError("sub must be a non-empty string")
    if name not in state.issuers:
        raise ControlError("unknown issuer")
    base = request.get("base", host_base)
    if not isinstance(base, str) or not re.match(r"^https?://[^/?#]+$", base):
        raise ControlError("base must be scheme://host[:port] without path")
    fmt = request.get("format", "jwt")
    expires_in = request.get("expires_in", 3600)
    extra = request.get("claims", {})
    userinfo = request.get("userinfo", {})
    header = request.get("header", {})
    if fmt not in ("jwt", "opaque"):
        raise ControlError("format must be jwt or opaque")
    if not isinstance(expires_in, int) or isinstance(expires_in, bool):
        raise ControlError("expires_in must be an integer")
    if not all(isinstance(x, dict) for x in (extra, userinfo, header)):
        raise ControlError("claims, userinfo and header must be objects")
    now = int(time.time())
    iss = f"{base}/{name}"
    exp = now + expires_in
    kid = None
    if fmt == "opaque":
        token = secrets.token_urlsafe(32)
    else:
        claims: dict[str, Any] = {
            "iss": iss,
            "sub": sub,
            "aud": request.get("aud", DEFAULT_AUDIENCE),
            "iat": now,
            "exp": exp,
            "jti": secrets.token_hex(8),
        }
        if "scope" in request:
            claims["scope"] = request["scope"]
        claims.update(extra)
        alg = request.get("alg", "RS256")
        if alg not in ("RS256", "none"):
            raise ControlError("alg must be RS256 or none")
        key = state.signing_key(name, str(request.get("key", "active"))) if alg == "RS256" else None
        kid = key.kid if key else None
        token = encode_jwt(claims, key, alg, header)
        if isinstance(claims.get("exp"), int | float):
            exp = claims["exp"]
    state.remember(token, TokenRecord(name, sub, exp, copy.deepcopy(userinfo)))
    return {"access_token": token, "token_type": "Bearer", "expires_in": expires_in, "iss": iss, "kid": kid}


def check_behaviour(behaviour: dict[str, Any]) -> None:
    """Validate one userinfo behaviour.

    Args:
        behaviour: The behaviour.

    Raises:
        ControlError: If a field has the wrong type or value.
    """
    if behaviour.get("mode", "json") not in ("json", "jwt"):
        raise ControlError("mode must be json or jwt")
    status = behaviour.get("status", 200)
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        raise ControlError("status must be an HTTP status code")
    delay = behaviour.get("delay", 0)
    if not isinstance(delay, int | float) or isinstance(delay, bool) or not 0 <= delay <= 60:
        raise ControlError("delay must be a number of seconds from 0 to 60")
    if not isinstance(behaviour.get("close", False), bool):
        raise ControlError("close must be a boolean")
    for key in ("sub", "content_type"):
        if key in behaviour and not isinstance(behaviour[key], str):
            raise ControlError(f"{key} must be a string")


def discovery(issuer: str) -> dict[str, Any]:
    """Build the discovery document (OpenID Connect Discovery 1.0).

    Args:
        issuer: The issuer URL.

    Returns:
        The document.
    """
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "userinfo_signing_alg_values_supported": ["RS256"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "scopes_supported": ["openid", "profile", "email", "eduperson_entitlement"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "scope", "eduperson_entitlement"],
    }


def make_handler(state: State) -> type[BaseHTTPRequestHandler]:
    """Build the handler class bound to one state.

    Args:
        state: The shared state.

    Returns:
        The handler class.
    """

    class Handler(BaseHTTPRequestHandler):
        """Mock OIDC issuer handler."""

        server_version = "tes-authz-oidc"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            """Route access logs to the module logger.

            Args:
                format: The format string.
                *args: The format arguments.
            """
            log.debug(format, *args)

        def _send(self, status: int, text: str, content_type: str, headers: dict[str, str] | None = None) -> None:
            data = text.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)

        def _json(self, status: int, body: Any, headers: dict[str, str] | None = None) -> None:
            self._send(status, json.dumps(body), "application/json", headers)

        def _host_base(self) -> str:
            host = self.headers.get("Host") or "localhost"
            return f"http://{host}"

        def _body(self) -> Any:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length > MAX_BODY_BYTES:
                raise ControlError("body too large")
            raw = self.rfile.read(length) if length > 0 else b""
            if not raw:
                return {}
            try:
                return json.loads(raw)
            except ValueError as exc:
                raise ControlError("body is not JSON") from exc

        def _issuer_path(self) -> tuple[str, str] | None:
            path = self.path.split("?", 1)[0]
            name, _, rest = path.lstrip("/").partition("/")
            if name in state.issuers:
                return name, "/" + rest
            return None

        def do_GET(self) -> None:
            """Serve discovery, JWKS, userinfo, health and recordings."""
            if self.path == "/health":
                self._json(HTTPStatus.OK, {"status": "ok"})
                return
            if self.path == "/_control/userinfo-calls":
                with state.lock:
                    self._json(HTTPStatus.OK, state.calls)
                return
            target = self._issuer_path()
            if target is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            name, rest = target
            issuer = f"{self._host_base()}/{name}"
            if rest == "/.well-known/openid-configuration":
                self._json(HTTPStatus.OK, discovery(issuer))
            elif rest == "/jwks":
                self._send(HTTPStatus.OK, json.dumps(state.jwks(name)), "application/jwk-set+json")
            elif rest == "/userinfo":
                self._userinfo(name, issuer)
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_PUT(self) -> None:
            """Set userinfo behaviours."""
            if self.path != "/_control/userinfo":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            try:
                body = self._body()
                default = body.get("default", DEFAULT_BEHAVIOUR) if isinstance(body, dict) else None
                subjects = body.get("subjects", {}) if isinstance(body, dict) else None
                if not isinstance(default, dict) or not isinstance(subjects, dict):
                    raise ControlError("default and subjects must be objects")
                if not all(isinstance(v, dict) for v in subjects.values()):
                    raise ControlError("each subject behaviour must be an object")
                for behaviour in (default, *subjects.values()):
                    check_behaviour(behaviour)
            except ControlError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            with state.lock:
                state.behaviour = {"default": default, "subjects": subjects}
            self._json(HTTPStatus.OK, {"default": default, "subjects": subjects})

        def do_POST(self) -> None:
            """Serve userinfo, the token endpoint and the control API."""
            target = self._issuer_path()
            if target is not None:
                name, rest = target
                if rest == "/userinfo":
                    self._userinfo(name, f"{self._host_base()}/{name}")
                elif rest == "/token":
                    self._json(
                        HTTPStatus.BAD_REQUEST,
                        {"error": "unsupported_grant_type", "error_description": "use the control API"},
                    )
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            try:
                body = self._body()
                if self.path == "/_control/tokens":
                    self._json(HTTPStatus.OK, mint(state, body, self._host_base()))
                elif self.path == "/_control/keys/rotate":
                    name = self._known_issuer(body)
                    kid = state.rotate(name, bool(body.get("keep_previous", True)))
                    self._json(HTTPStatus.OK, {"kid": kid, "jwks": state.jwks(name)})
                elif self.path == "/_control/keys/retire":
                    name = self._known_issuer(body)
                    state.retire(name, str(body.get("kid")))
                    self._json(HTTPStatus.OK, {"jwks": state.jwks(name)})
                elif self.path == "/_control/reset":
                    state.reset(keys=bool(body.get("keys", False)) if isinstance(body, dict) else False)
                    self._json(HTTPStatus.OK, {"status": "reset"})
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            except ControlError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

        @staticmethod
        def _known_issuer(body: Any) -> str:
            name = body.get("issuer", next(iter(state.issuers))) if isinstance(body, dict) else None
            if name not in state.issuers:
                raise ControlError("unknown issuer")
            return str(name)

        def _userinfo(self, name: str, issuer: str) -> None:
            header = self.headers.get("Authorization", "")
            token = header[7:].strip() if header[:7].lower() == "bearer " else None
            record = state.lookup(token) if token else None
            valid = record is not None and record.issuer == name and record.exp > time.time()
            behaviour = state.behaviour_for(record.sub if record else None)
            mode = str(behaviour.get("mode", "json"))
            status = int(behaviour.get("status", 200))
            # Record on arrival, before any delay: a delayed call must not
            # show up after a later reset (it would count for the next test).
            if behaviour.get("close"):
                outcome = 0
            elif not valid or record is None:
                outcome = HTTPStatus.UNAUTHORIZED
            else:
                outcome = status
            state.record_call(name, token, record.sub if record else None, outcome, mode)
            if behaviour.get("delay"):
                time.sleep(float(behaviour["delay"]))
            if behaviour.get("close"):
                self.close_connection = True
                return
            if not valid or record is None:
                self._json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "invalid_token"},
                    {"WWW-Authenticate": 'Bearer error="invalid_token"'},
                )
                return
            if status != HTTPStatus.OK:
                self._json(status, {"error": "server_error"})
                return
            claims = {"sub": record.sub, **record.userinfo}
            if "sub" in behaviour:
                claims["sub"] = behaviour["sub"]
            if mode == "jwt":
                now = int(time.time())
                signed = encode_jwt(
                    {**claims, "iss": issuer, "aud": DEFAULT_AUDIENCE, "iat": now, "exp": int(record.exp)},
                    state.signing_key(name, "active"),
                )
                self._send(status, signed, str(behaviour.get("content_type", "application/jwt")))
            else:
                self._send(status, json.dumps(claims), str(behaviour.get("content_type", "application/json")))

    return Handler


def make_server(
    port: int,
    names: list[str] | None = None,
    key_bits: int = 2048,
    host: str = "0.0.0.0",  # noqa: S104
) -> tuple[ThreadingHTTPServer, State]:
    """Create an issuer server (not yet serving).

    Args:
        port: The TCP port (0 picks a free one).
        names: Issuer names (default ``a`` and ``b``).
        key_bits: RSA modulus size.
        host: The address to bind.

    Returns:
        The server and its state.
    """
    state = State(["a", "b"] if names is None else names, key_bits)
    server = ThreadingHTTPServer((host, port), make_handler(state))
    server.daemon_threads = True
    return server, state


def main() -> None:
    """Run the issuer until interrupted."""
    logging.basicConfig(level=os.environ.get("OIDC_LOG_LEVEL", "INFO"))
    names = [n.strip() for n in os.environ.get("OIDC_ISSUERS", "a,b").split(",") if n.strip()]
    server, _ = make_server(
        int(os.environ.get("OIDC_PORT", "8080")), names, int(os.environ.get("OIDC_KEY_BITS", "2048"))
    )
    log.info("issuers %s listening on port %d", ", ".join(names), server.server_address[1])
    server.serve_forever()


if __name__ == "__main__":
    main()

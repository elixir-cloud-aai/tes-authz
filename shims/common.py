"""Generic shim steps shared by every engine shim (no policy here).

The module is standard-library only, so a shim container needs nothing but
a Python image. It holds the steps that the spec (draft 3, section 7)
assigns to all shims:

* contract validation of an incoming AuthZEN Access Evaluation request
  against the ``tes-authzen/1`` profile;
* prefix expansion of list-valued claims, for engines without quantifiers;
* normalisation of claim values to a list of strings;
* identifier encoding for engines with identifier pattern or length limits;
* a tiny JSON-over-HTTP server and client used by the shims.

It also carries the reference implementation of the TES-side URL stripping
algorithm (section 3.3), so that the golden URL cases have one executable
definition next to the suite.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PROFILE = "tes-authzen/1"
"""Profile version that the TES sends in ``context.tes.profile``."""

ACTIONS = frozenset({"CreateTask", "GetTask", "ListTasks", "CancelTask"})
"""Action names of the profile (TES OpenAPI operation IDs)."""

RESOURCE_TYPES = frozenset({"tes_task", "tes_task_set"})
"""Resource types of the profile."""

TASK_SET_IDS = frozenset({"own", "all"})
"""Fixed task set IDs of the profile."""

MAX_BODY_BYTES = int(os.environ.get("SHIM_MAX_BODY_BYTES", str(1024 * 1024)))
"""Largest request body a shim accepts (``SHIM_MAX_BODY_BYTES``).

The OpenFGA shim needs less than OpenFGA's gRPC receive limit (about 602 KiB).
"""

SOCKET_TIMEOUT = 5.0
"""Seconds a socket read may stay idle (per read, not per request).

Total request time and the number of connections are not bounded here;
a deployment limits them in the mesh or gateway in front of the shim.
"""

log = logging.getLogger("tes-authz-shim")


class ContractError(ValueError):
    """Raised when a request does not follow the ``tes-authzen/1`` profile."""


def validate_request(req: Any) -> None:
    """Check that a request follows the AuthZEN mapping of the profile.

    The check is structural only: it decides nothing about who may do what.
    A request that fails it is denied by the shim (``decision: false``),
    which is what the reference policy would answer for it as well.

    Args:
        req: The decoded JSON request body.

    Raises:
        ContractError: If the request does not follow the profile.
    """
    if not isinstance(req, dict):
        raise ContractError("request is not a JSON object")
    subject = req.get("subject")
    action = req.get("action")
    resource = req.get("resource")
    context = req.get("context")
    if not isinstance(subject, dict) or subject.get("type") != "user":
        raise ContractError("subject.type must be 'user'")
    if not isinstance(subject.get("id"), str) or not subject["id"]:
        raise ContractError("subject.id must be a non-empty string")
    if not isinstance(action, dict) or action.get("name") not in ACTIONS:
        raise ContractError("action.name is not a TES operation")
    if not isinstance(resource, dict) or resource.get("type") not in RESOURCE_TYPES:
        raise ContractError("resource.type is not a TES resource type")
    if not isinstance(resource.get("id"), str) or not resource["id"]:
        raise ContractError("resource.id must be a non-empty string")
    if resource["type"] == "tes_task_set" and resource["id"] not in TASK_SET_IDS:
        raise ContractError("unknown task set")
    for name, value in (
        ("subject.properties", subject.get("properties", {})),
        ("action.properties", action.get("properties", {})),
        ("resource.properties", resource.get("properties", {})),
    ):
        if not isinstance(value, dict):
            raise ContractError(f"{name} must be an object")
    tes = context.get("tes") if isinstance(context, dict) else None
    if not isinstance(tes, dict) or tes.get("profile") != PROFILE:
        raise ContractError("context.tes.profile is missing or unsupported")
    if not isinstance(tes.get("service_id"), str) or not tes["service_id"]:
        raise ContractError("context.tes.service_id must be a non-empty string")
    try:
        json.dumps(req, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError as exc:
        # Lone surrogates: engines would decode them differently (Go maps
        # them to U+FFFD, so distinct IDs could compare equal).
        raise ContractError("request contains strings that are not valid UTF-8") from exc


def string_list(value: Any) -> list[str]:
    """Normalise a claim value to a list of strings.

    A string becomes a one-element list; a list keeps its string elements;
    anything else (missing, number, object) becomes an empty list. Engines
    with typed condition parameters (OpenFGA) need the parameter to be
    present and well-typed, so a shim never passes the raw value.

    Args:
        value: The claim value as found in ``subject.properties.claims``.

    Returns:
        The string values of the claim.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def expand_prefixes(values: Iterable[str], delimiters: str = ":") -> list[str]:
    """Add, for each value, its prefixes that end at a delimiter.

    ``a:b:c#x`` becomes ``a:``, ``a:b:`` and ``a:b:c#x``. Engines without a
    quantifier over sets (Cedar, Casbin) can then test "has a subgroup of
    ``a:b:``" as plain set membership. The result is equivalent to a raw
    ``startswith`` test only for prefixes that end in a delimiter.

    Args:
        values: The claim values.
        delimiters: The characters at which prefixes end (a shim setting;
            default ``:``, e.g. ``/`` for Keycloak group paths).

    Returns:
        The values and their delimiter-terminated prefixes, sorted and
        without duplicates.
    """
    expanded: set[str] = set()
    for value in values:
        expanded.add(value)
        for index, char in enumerate(value):
            if char in delimiters:
                expanded.add(value[: index + 1])
    return sorted(expanded)


_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,200}$")


def encode_id(value: str) -> str:
    r"""Encode an identifier for engines with identifier limits.

    Plain identifiers stay readable; anything else (``https://iss|sub``,
    long values, values starting with ``h-``) becomes ``h-`` plus the
    SHA-256 hex digest, which fits OpenFGA's ``^[^:#@\s]{1,256}$`` and
    cannot collide with a plain identifier.

    Args:
        value: The identifier.

    Returns:
        An identifier that is safe for OpenFGA objects and users.
    """
    if _SAFE_ID.fullmatch(value) and not value.startswith("h-"):
        return value
    return "h-" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_id(value: str) -> str:
    """Hash an identifier unconditionally (``h-`` plus SHA-256 hex).

    Args:
        value: The identifier.

    Returns:
        The hashed identifier.
    """
    return "h-" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def strip_url(value: str) -> str | None:
    """Strip credentials from a URL with the plain string rule of the spec.

    This is the TES-side projection rule (spec section 3.3), kept here as
    the executable definition of the golden URL cases:

    1. Cut the value at the first ``?`` or ``#``.
    2. If it contains ``://``: in the authority (from after ``://`` to the
       next ``/``, or the end), drop everything up to and including the last
       ``@``.
    3. If it has no ``://``: keep it unchanged if it contains no ``@``;
       otherwise omit the field (``None``).
    4. No other normalisation.

    Args:
        value: The URL as submitted.

    Returns:
        The stripped URL, or ``None`` if the field must be omitted.
    """
    for index, char in enumerate(value):
        if char in "?#":
            value = value[:index]
            break
    marker = value.find("://")
    if marker < 0:
        return value if "@" not in value else None
    start = marker + 3
    end = value.find("/", start)
    authority = value[start:] if end < 0 else value[start:end]
    rest = "" if end < 0 else value[end:]
    at = authority.rfind("@")
    if at >= 0:
        authority = authority[at + 1 :]
    return value[:start] + authority + rest


class UpstreamError(RuntimeError):
    """Raised when an engine answers with an error or an invalid body."""


def post_json(url: str, body: Any, timeout: float, headers: dict[str, str] | None = None) -> Any:
    """POST a JSON body and decode the JSON answer.

    Args:
        url: The target URL.
        body: The JSON-serialisable body.
        timeout: Timeout in seconds.
        headers: Extra request headers.

    Returns:
        The decoded JSON response.

    Raises:
        UpstreamError: On a connection error, a non-2xx status or a body
            that is not JSON.
    """
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:500].decode("utf-8", "replace")
        raise UpstreamError(f"upstream status {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise UpstreamError(f"upstream failure: {exc}") from exc


Decide = Callable[[dict[str, Any], dict[str, str]], bool]
"""A shim's decision function: request and forwarded headers to a decision."""


def make_handler(decide: Decide, metadata: dict[str, Any]) -> type[BaseHTTPRequestHandler]:
    """Build an HTTP handler that serves the AuthZEN evaluation endpoint.

    The handler validates the request against the profile (an invalid
    request is a deny), calls ``decide`` and answers ``{"decision": bool}``.
    An engine failure becomes ``502`` so that the TES fails closed with 503.

    Args:
        decide: The engine-specific decision function.
        metadata: The body of ``/.well-known/authzen-configuration``.

    Returns:
        The handler class.
    """

    class Handler(BaseHTTPRequestHandler):
        """AuthZEN front for one engine."""

        server_version = "tes-authz-shim"
        sys_version = ""
        timeout = SOCKET_TIMEOUT

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            """Route access logs to the module logger.

            Args:
                format: The format string.
                *args: The format arguments.
            """
            log.debug(format, *args)

        def _send(self, status: int, body: Any, request_id: str | None = None) -> None:
            data = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            if request_id:
                self.send_header("X-Request-ID", request_id)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            """Serve metadata and a health endpoint."""
            if self.path == "/.well-known/authzen-configuration":
                self._send(HTTPStatus.OK, metadata)
            elif self.path == "/health":
                self._send(HTTPStatus.OK, {"status": "ok"})
            else:
                self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:
            """Serve the AuthZEN Access Evaluation endpoint."""
            request_id = self.headers.get("X-Request-ID")
            if self.path != "/access/v1/evaluation":
                self._send(HTTPStatus.NOT_FOUND, {"error": "not found"}, request_id)
                return
            if "Content-Length" not in self.headers or self.headers.get("Transfer-Encoding"):
                self._send(HTTPStatus.LENGTH_REQUIRED, {"error": "Content-Length required"}, request_id)
                return
            try:
                length = int(self.headers["Content-Length"])
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY_BYTES:
                self._send(HTTPStatus.BAD_REQUEST, {"error": "bad length"}, request_id)
                return
            try:
                req = json.loads(self.rfile.read(length) or b"null")
            except ValueError:
                self._send(HTTPStatus.BAD_REQUEST, {"error": "body is not JSON"}, request_id)
                return
            try:
                validate_request(req)
            except ContractError as exc:
                log.info("deny (contract): %s request_id=%s", exc, request_id)
                self._send(HTTPStatus.OK, {"decision": False}, request_id)
                return
            forward = {"X-Request-ID": request_id} if request_id else {}
            try:
                decision = decide(req, forward)
            except UpstreamError as exc:
                log.warning("engine error: %s request_id=%s", exc, request_id)
                self._send(HTTPStatus.BAD_GATEWAY, {"error": "decision engine error"}, request_id)
                return
            except Exception:
                log.exception("shim error request_id=%s", request_id)
                self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "shim error"}, request_id)
                return
            log.info(
                "decision=%s action=%s resource=%s:%s request_id=%s",
                decision,
                req["action"]["name"],
                req["resource"]["type"],
                req["resource"]["id"],
                request_id,
            )
            self._send(HTTPStatus.OK, {"decision": decision}, request_id)

    return Handler


def serve(port: int, decide: Decide, metadata: dict[str, Any]) -> None:
    """Run a shim server until interrupted.

    Args:
        port: The TCP port to listen on (all interfaces, inside a container).
        decide: The engine-specific decision function.
        metadata: The body of ``/.well-known/authzen-configuration``.
    """
    server = ThreadingHTTPServer(("0.0.0.0", port), make_handler(decide, metadata))  # noqa: S104
    log.info("listening on port %d", port)
    server.serve_forever()

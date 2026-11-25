"""Minimal in-memory TES with the AuthZ hook of spec draft 3, section 6 (``tes-authzen/3``).

Test-only. It exists to exercise the harness (stub, golden comparison,
engines) end to end before a real TES has the hook, and as executable
pseudo-code of the hook. It is not a TES implementation:

* AuthN is OIDC against the harness's mock issuer (``oidc/issuer.py``):
  RS256 access tokens validated with the pinned issuers' JWKS (issuer,
  audience, expiry; JWKS refetched once on an unknown key ID), and the
  optional userinfo lookup of spec section 3.6 (``sub`` must match, JSON
  only, cached by token hash until min(``exp``, 5 minutes)). With more than
  one issuer, owners are ``<iss>|<sub>``.
* No executors, no backend; tasks stay ``QUEUED``.
* Operations (spec section 3): with a decision service, ``CreateTask`` always
  asks it; ``GetTask``, ``ListTasks`` and ``CancelTask`` ask it only when
  switched on (``authz.operations``), and otherwise follow the owner rule
  without a call. A switched-on operation is decided by the decision
  service alone, which may widen it beyond the owner; ``ListTasks`` then
  takes the list scope (``own``, ``all`` or ``none``) from the answer.
* Failure per operation (``authz.failure.<operation>``): ``closed`` (the
  default) answers 503; ``open`` falls back to the owner rule (never to
  allow-all), and is refused for ``create`` at start.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shims"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "oidc"))

from common import strip_url
from minijose import JoseError, UnknownKeyError, decode_unverified, verify_jwt

log = logging.getLogger("tes-authz-mock-tes")

PREFIX = "/ga4gh/tes/v1"
PROFILE = "tes-authzen/3"
USERINFO_TTL = 300.0
"""Longest time a userinfo answer is cached (spec section 3.6)."""
USERINFO_CACHE_SIZE = 1024
"""Most userinfo answers cached (LRU)."""
MAX_BODY_BYTES = 1024 * 1024
"""Largest request body read; longer ones are answered with 413, unread.

As the default of the shims' ``SHIM_MAX_BODY_BYTES`` (``shims/common.py``).
"""
SOCKET_TIMEOUT = 5.0
"""Seconds a socket read may stay idle, as in the shims."""
OPERATIONS = ("create", "get", "list", "cancel")
"""Values of ``authz.operations`` and keys of ``authz.failure`` (spec section 4.2)."""
FAILURE_MODES = ("closed", "open")
"""Values of ``authz.failure.<operation>`` (spec section 4.1)."""
LIST_SCOPES = ("own", "all", "none")
"""Values of the response's ``context.tes.list_scope`` (spec section 3.5)."""


class HttpError(Exception):
    """An HTTP error answer."""

    def __init__(self, status: int, message: str) -> None:
        """Create the error.

        Args:
            status: HTTP status.
            message: Message for the body.
        """
        super().__init__(message)
        self.status = status


@dataclass
class Settings:
    """Hook settings (spec section 4.2).

    Attributes:
        pdp_url: ``authz.decisionService.url``; ``None`` = built-in owner rule.
        timeout: ``authz.decisionService.timeout``.
        claims: ``authz.decisionService.claims``.
        rule_name: ``authz.requiredClaim.name``.
        rule_values: ``authz.requiredClaim.values``.
        rule_prefixes: ``authz.requiredClaim.prefixes``.
        service_id: Service-info ID.
        issuers: Pinned issuer URLs; more than one gives ``<iss>|<sub>``
            owners. Without any, every request with a token is 401.
        audience: The ``aud`` access tokens must carry.
        userinfo: ``auth.oidc.userinfo.enabled``.
        userinfo_timeout: Seconds for one discovery, JWKS or userinfo call.
        operations: ``authz.operations``: the operations the decision
            service decides (``create`` always among them).
        failure: ``authz.failure.<operation>``: ``closed`` (default) or
            ``open`` per operation.
    """

    pdp_url: str | None = None
    timeout: float = 2.0
    claims: tuple[str, ...] = ()
    rule_name: str | None = None
    rule_values: tuple[str, ...] = ()
    rule_prefixes: tuple[str, ...] = ()
    service_id: str = "tes-authz-test"
    issuers: tuple[str, ...] = ()
    audience: str = "tes-authz"
    userinfo: bool = False
    userinfo_timeout: float = 2.0
    operations: tuple[str, ...] = ("create",)
    failure: dict[str, str] = field(default_factory=dict)


def check_settings(settings: Settings) -> None:
    """Apply the startup checks of the operation switch (spec section 4.2).

    Args:
        settings: The settings.

    Raises:
        ValueError: If the TES must refuse to start: a switch other than the
            default without a decision service, an unknown or repeated
            operation, an unknown failure mode, or ``create`` missing from
            ``operations`` or set to ``open``.
    """
    if settings.pdp_url is None and (tuple(settings.operations) != ("create",) or settings.failure):
        raise ValueError("authz.operations and authz.failure need authz.decisionService.url")
    unknown = [op for op in (*settings.operations, *settings.failure) if op not in OPERATIONS]
    if unknown:
        raise ValueError(f"unknown operation(s): {unknown}")
    if len(set(settings.operations)) != len(settings.operations):
        raise ValueError("authz.operations lists an operation twice")
    modes = [mode for mode in settings.failure.values() if mode not in FAILURE_MODES]
    if modes:
        raise ValueError(f"unknown failure mode(s): {modes}")
    if "create" not in settings.operations:
        raise ValueError("authz.operations must contain create")
    if settings.failure.get("create", "closed") != "closed":
        raise ValueError("authz.failure.create must be closed: the TES has no create rule to fall back to")


@dataclass
class Principal:
    """The authenticated caller.

    Attributes:
        claims: The validated access-token claims.
        userinfo: Userinfo claims (empty when userinfo is off).
        owner_id: ``sub``, or ``<iss>|<sub>`` with several issuers.
    """

    claims: dict[str, Any]
    userinfo: dict[str, Any] = field(default_factory=dict)
    owner_id: str = ""


@dataclass
class Store:
    """In-memory task store with a keyset cursor.

    Attributes:
        tasks: Tasks by ID.
        order: Insertion sequence number by ID.
    """

    tasks: dict[str, dict[str, Any]] = field(default_factory=dict)
    order: dict[str, int] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


_MISSING = object()


def _path(claims: dict[str, Any], name: str) -> Any:
    node: Any = claims
    for part in name.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


def lookup(p: Principal, name: str) -> Any:
    """Look a claim up in the resolved claim view (spec section 6).

    First found of: token[name], userinfo[name], path(token, name),
    path(userinfo, name).

    Args:
        p: The caller.
        name: The claim name.

    Returns:
        The value, or ``_MISSING``.
    """
    for source in (p.claims, p.userinfo):
        if name in source:
            return source[name]
    for source in (p.claims, p.userinfo):
        value = _path(source, name)
        if value is not _MISSING:
            return value
    return _MISSING


class DecisionServiceError(HttpError):
    """A failed decision (timeout, connection error, malformed answer): 503 when failing closed."""

    def __init__(self) -> None:
        """Create the error."""
        super().__init__(HTTPStatus.SERVICE_UNAVAILABLE, "decision service unavailable")


def list_scope(answer: dict[str, Any]) -> str:
    """Read the list scope from a ``ListTasks`` answer (spec section 3.5).

    A deny is ``none``; an allow without ``context.tes.list_scope`` is
    ``own``, so plain AuthZEN PDPs answer ``own`` or ``none``.

    Args:
        answer: The decision service's answer, ``decision`` a boolean.

    Returns:
        ``own``, ``all`` or ``none``.

    Raises:
        DecisionServiceError: If ``context``, ``context.tes`` or
            ``list_scope`` is present but malformed or unknown.
    """
    if answer["decision"] is not True:
        return "none"
    context = answer.get("context", {})
    tes = context.get("tes", {}) if isinstance(context, dict) else None
    scope = tes.get("list_scope", "own") if isinstance(tes, dict) else None
    if not isinstance(scope, str) or scope not in LIST_SCOPES:
        raise DecisionServiceError
    return scope


class UnauthorizedError(HttpError):
    """A 401 answer."""

    def __init__(self) -> None:
        """Create the error."""
        super().__init__(HTTPStatus.UNAUTHORIZED, "unauthorized")


def _get_json(url: str, timeout: float, content_types: tuple[str, ...], token: str | None = None) -> Any:
    """GET a JSON document; any failure or non-JSON answer is ``UnauthorizedError``.

    Args:
        url: The URL.
        timeout: Seconds.
        content_types: Accepted media types (parameters ignored).
        token: Bearer token to send, if any.

    Returns:
        The decoded body.

    Raises:
        UnauthorizedError: On error, timeout, non-200, or a content type other
            than JSON (signed userinfo, ``application/jwt``, is refused).
    """
    request = urllib.request.Request(url)
    if token is not None:
        request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            received = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
            if response.status != HTTPStatus.OK or received not in content_types:
                raise UnauthorizedError
            return json.loads(response.read())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise UnauthorizedError from exc


class OidcAuth:
    """OIDC AuthN: token validation against pinned issuers, optional userinfo."""

    def __init__(self, settings: Settings) -> None:
        """Bind to the settings; discovery and JWKS are fetched on first use.

        Args:
            settings: The TES settings.
        """
        self.settings = settings
        self.lock = threading.Lock()
        self.discovery: dict[str, dict[str, Any]] = {}
        self.jwks: dict[str, dict[str, Any]] = {}
        self.userinfo_cache: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()

    def _discovery(self, issuer: str) -> dict[str, Any]:
        with self.lock:
            cached = self.discovery.get(issuer)
        if cached is None:
            doc = _get_json(
                issuer + "/.well-known/openid-configuration", self.settings.userinfo_timeout, ("application/json",)
            )
            if not isinstance(doc, dict) or doc.get("issuer") != issuer:
                raise UnauthorizedError
            cached = doc
            with self.lock:
                self.discovery[issuer] = doc
        return cached

    def _jwks(self, issuer: str, refresh: bool) -> dict[str, Any]:
        with self.lock:
            cached = None if refresh else self.jwks.get(issuer)
        if cached is None:
            jwks = _get_json(
                str(self._discovery(issuer).get("jwks_uri")),
                self.settings.userinfo_timeout,
                ("application/jwk-set+json", "application/json"),
            )
            if not isinstance(jwks, dict):
                raise UnauthorizedError
            cached = jwks
            with self.lock:
                self.jwks[issuer] = jwks
        return cached

    def authenticate(self, header: str | None) -> Principal:
        """Validate the bearer token and resolve userinfo.

        Args:
            header: The ``Authorization`` header.

        Returns:
            The caller.

        Raises:
            UnauthorizedError: On any AuthN failure.
        """
        if not header or not header.startswith("Bearer "):
            raise UnauthorizedError
        token = header.removeprefix("Bearer ").strip()
        try:
            # Only `iss` is read, to pick a pinned issuer's JWKS; the claims
            # come from `verify_jwt()` below
            # ast-grep-ignore: unverified-token-claims
            _, unverified = decode_unverified(token)
        except JoseError as exc:
            raise UnauthorizedError from exc
        issuer = unverified.get("iss")
        if not isinstance(issuer, str) or issuer not in self.settings.issuers:
            raise UnauthorizedError
        claims: dict[str, Any] = {}
        for refresh in (False, True):
            try:
                claims = verify_jwt(token, self._jwks(issuer, refresh), issuer, self.settings.audience)
                break
            except JoseError as exc:
                if refresh or not isinstance(exc, UnknownKeyError):
                    raise UnauthorizedError from exc
        owner = claims["sub"] if len(self.settings.issuers) == 1 else f"{issuer}|{claims['sub']}"
        userinfo = self._userinfo(issuer, token, claims) if self.settings.userinfo else {}
        return Principal(claims, userinfo, owner)

    def _userinfo(self, issuer: str, token: str, claims: dict[str, Any]) -> dict[str, Any]:
        key = hashlib.sha256(token.encode()).hexdigest()
        now = time.time()
        with self.lock:
            hit = self.userinfo_cache.get(key)
            if hit is not None and hit[0] > now:
                self.userinfo_cache.move_to_end(key)
                return hit[1]
        endpoint = self._discovery(issuer).get("userinfo_endpoint")
        if not isinstance(endpoint, str):
            raise UnauthorizedError
        info = _get_json(endpoint, self.settings.userinfo_timeout, ("application/json",), token)
        if not isinstance(info, dict) or info.get("sub") != claims["sub"]:
            raise UnauthorizedError
        with self.lock:
            self.userinfo_cache[key] = (min(float(claims["exp"]), now + USERINFO_TTL), info)
            while len(self.userinfo_cache) > USERINFO_CACHE_SIZE:
                self.userinfo_cache.popitem(last=False)
        return info


def project(task: dict[str, Any]) -> dict[str, Any]:
    """Project a submitted task for ``CreateTask`` (spec section 3.3).

    Args:
        task: The submitted task, already checked to have a list of
            executors with string images.

    Returns:
        The fixed projection.
    """
    out: dict[str, Any] = {}
    for key in ("name", "tags", "volumes"):
        if key in task:
            out[key] = task[key]
    if isinstance(task.get("resources"), dict):
        out["resources"] = {
            k: v
            for k, v in task["resources"].items()
            if k in ("cpu_cores", "ram_gb", "disk_gb", "preemptible", "zones")
        }
    out["executors"] = [{"image": ex["image"]} for ex in task["executors"]]
    for key in ("inputs", "outputs"):
        items = []
        for item in task.get(key, []) or []:
            if not isinstance(item, dict):
                continue
            entry = {k: item[k] for k in ("path", "type") if k in item}
            if isinstance(item.get("url"), str):
                stripped = strip_url(item["url"])
                if stripped is not None:
                    entry["url"] = stripped
            items.append(entry)
        if key in task:
            out[key] = items
    return out


class Hook:
    """The AuthZ hook bound to settings and a store."""

    def __init__(self, settings: Settings, store: Store) -> None:
        """Bind the hook.

        Args:
            settings: The hook settings.
            store: The task store.
        """
        self.settings = settings
        self.store = store

    def subject(self, p: Principal) -> dict[str, Any]:
        """Build the AuthZEN subject.

        Args:
            p: The caller.

        Returns:
            The subject.
        """
        c = p.claims
        props: dict[str, Any] = {k: c[k] for k in ("iss", "sub") if k in c}
        client_id = c.get("azp", c.get("client_id"))
        if client_id is not None:
            props["client_id"] = client_id
        if isinstance(c.get("scope"), str):
            props["scope"] = c["scope"].split()
        elif isinstance(c.get("scope"), list):
            props["scope"] = c["scope"]
        claims = {}
        for name in self.settings.claims:
            value = lookup(p, name)
            if value is not _MISSING:
                claims[name] = value
        props["claims"] = claims
        return {"type": "user", "id": p.owner_id, "properties": props}

    def gate(self, p: Principal) -> None:
        """Apply the built-in claim rule (``CreateTask`` only, spec section 5).

        Args:
            p: The caller.

        Raises:
            HttpError: 403 if the rule is set and fails.
        """
        if not self.settings.rule_name:
            return
        value = lookup(p, self.settings.rule_name)
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise HttpError(HTTPStatus.FORBIDDEN, "forbidden")
        if any(
            x in self.settings.rule_values or any(x.startswith(q) for q in self.settings.rule_prefixes) for x in value
        ):
            return
        raise HttpError(HTTPStatus.FORBIDDEN, "forbidden")

    def ask(
        self, p: Principal, action: str, resource: dict[str, Any], aprops: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Ask the decision service.

        Args:
            p: The caller.
            action: The action name.
            resource: The resource.
            aprops: Action properties.

        Returns:
            The answer, whose ``decision`` is a boolean.

        Raises:
            DecisionServiceError: On any failure.
        """
        assert self.settings.pdp_url is not None
        body = {
            "subject": self.subject(p),
            "action": {"name": action, "properties": aprops or {}},
            "resource": resource,
            "context": {"tes": {"profile": PROFILE, "service_id": self.settings.service_id}},
        }
        request = urllib.request.Request(self.settings.pdp_url, data=json.dumps(body).encode(), method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("X-Request-ID", str(uuid.uuid4()))
        try:
            with urllib.request.urlopen(request, timeout=self.settings.timeout) as response:
                if response.status != HTTPStatus.OK:
                    raise DecisionServiceError
                answer = json.loads(response.read())
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            raise DecisionServiceError from exc
        if not isinstance(answer, dict) or not isinstance(answer.get("decision"), bool):
            raise DecisionServiceError
        return answer

    def switched_on(self, operation: str) -> bool:
        """Tell whether the decision service decides an operation.

        Args:
            operation: ``create``, ``get``, ``list`` or ``cancel``.

        Returns:
            Whether a decision service is set and the operation is in
            ``authz.operations``.
        """
        return self.settings.pdp_url is not None and operation in self.settings.operations

    def fails_open(self, operation: str) -> bool:
        """Tell whether an operation falls back to the owner rule on a failed decision.

        Args:
            operation: The operation.

        Returns:
            Whether ``authz.failure.<operation>`` is ``open``.
        """
        return self.settings.failure.get(operation, "closed") == "open"

    @staticmethod
    def _meta(task: dict[str, Any] | None) -> dict[str, Any]:
        """Return a stored task's properties for a request (``{}`` when missing, spec section 3.7).

        Args:
            task: The stored task, or ``None``.

        Returns:
            Owner, state and tags, or ``{}``.
        """
        if task is None:
            return {}
        return {"owner": task["_owner"], "state": task["state"], "tags": task.get("tags", {})}

    def _lookup(self, task_id: str) -> dict[str, Any] | None:
        """Read a stored task; one without an exact owner counts as missing (spec section 3.3).

        Args:
            task_id: The task ID.

        Returns:
            The task, or ``None``.
        """
        task = self.store.tasks.get(task_id)
        if task is None or not isinstance(task.get("_owner"), str) or not task["_owner"]:
            return None
        return task

    def _in_scope(self, scope: str, p: Principal, task: dict[str, Any]) -> bool:
        """Tell whether a stored task is in a list scope (``own`` or ``all``).

        Args:
            scope: The list scope.
            p: The caller.
            task: The stored task.

        Returns:
            For ``all``, whether the task has an exact owner (spec section 3.3);
            for ``own``, whether the caller owns it.
        """
        if scope == "all":
            return isinstance(task.get("_owner"), str) and bool(task["_owner"])
        return self.owner_rule(p, task)

    @staticmethod
    def owner_rule(p: Principal, task: dict[str, Any] | None) -> bool:
        """Apply the TES's own owner rule.

        Args:
            p: The caller.
            task: The stored task, or ``None``.

        Returns:
            Whether the task exists and the caller owns it.
        """
        return task is not None and task["_owner"] == p.owner_id

    def fall_back(self, operation: str) -> None:
        """Handle a failed decision: re-raise when failing closed, else log the fallback.

        Args:
            operation: The operation.

        Raises:
            DecisionServiceError: If ``authz.failure.<operation>`` is ``closed``.
        """
        if not self.fails_open(operation):
            raise DecisionServiceError
        # Identifiers only: no token, no claim values (spec section 4.3)
        log.warning("decision failed; %s falls back to the owner rule (failure open)", operation)

    def task_decision(
        self, operation: str, p: Principal, task_id: str, task: dict[str, Any] | None, aprops: dict[str, Any]
    ) -> tuple[bool, bool]:
        """Decide ``get`` or ``cancel`` on one task ID (spec section 6).

        Switched on, the decision service decides, for every ID (missing ones
        too, so the calls don't tell whether a task exists); otherwise, or
        after a failed decision with ``open``, the owner rule decides.

        Args:
            operation: ``get`` or ``cancel``.
            p: The caller.
            task_id: The requested task ID.
            task: The stored task, or ``None``.
            aprops: Action properties.

        Returns:
            Whether the operation is allowed (the caller still checks that the
            task exists), and whether the decision service decided it.

        Raises:
            DecisionServiceError: On a failed decision with ``closed``.
        """
        if self.switched_on(operation):
            action = {"get": "GetTask", "cancel": "CancelTask"}[operation]
            resource = {"type": "tes_task", "id": task_id, "properties": self._meta(task)}
            try:
                return self.ask(p, action, resource, aprops)["decision"] is True, True
            except DecisionServiceError:
                self.fall_back(operation)
        return self.owner_rule(p, task), False

    def create(self, p: Principal, task: dict[str, Any]) -> dict[str, Any]:
        """CreateTask.

        Args:
            p: The caller.
            task: The submitted task.

        Returns:
            ``{"id": ...}``.

        Raises:
            HttpError: 403 on a failed claim rule or a deny, 400 on bad executors.
            DecisionServiceError: On a failed decision (503; create always fails closed).
        """
        self.gate(p)
        executors = task.get("executors")
        if not isinstance(executors, list) or not all(
            isinstance(ex, dict) and isinstance(ex.get("image"), str) for ex in executors
        ):
            raise HttpError(HTTPStatus.BAD_REQUEST, "executors must be a list of objects with an image")
        for key in ("id", "state", "creation_time", "logs"):
            task.pop(key, None)
        resource = {"type": "tes_task_set", "id": "own", "properties": {"owner": p.owner_id, "task": project(task)}}
        if self.switched_on("create") and self.ask(p, "CreateTask", resource)["decision"] is not True:
            raise HttpError(HTTPStatus.FORBIDDEN, "forbidden")
        task_id = str(uuid.uuid4())
        with self.store.lock:
            stored = {**task, "id": task_id, "state": "QUEUED", "_owner": p.owner_id}
            self.store.tasks[task_id] = stored
            self.store.order[task_id] = len(self.store.order)
        return {"id": task_id}

    def get(self, p: Principal, task_id: str, view: str) -> dict[str, Any]:
        """GetTask.

        Args:
            p: The caller.
            task_id: The task ID.
            view: The view.

        Returns:
            The task.

        Raises:
            HttpError: 404 on a deny or a missing task.
            DecisionServiceError: On a failed decision when failing closed (503).
        """
        task = self._lookup(task_id)
        allowed, _ = self.task_decision("get", p, task_id, task, {"view": view})
        if allowed is not True or task is None:
            raise HttpError(HTTPStatus.NOT_FOUND, "not found")
        return self._render(task, view)

    def cancel(self, p: Principal, task_id: str) -> dict[str, Any]:
        """CancelTask.

        Args:
            p: The caller.
            task_id: The task ID.

        Returns:
            ``{}``.

        Raises:
            HttpError: 404 on a missing task or a deny the caller may not
                read; 403 on a deny the caller may read.
            DecisionServiceError: On a failed decision when failing closed (503).
        """
        task = self._lookup(task_id)
        allowed, by_pdp = self.task_decision("cancel", p, task_id, task, {})
        if allowed is not True:
            # Denied: 403 only if the caller may read the task (case 11d). A
            # deny of the owner rule is decided by the owner rule alone, so an
            # operation that isn't switched on (or fell open) asks nothing more.
            readable = self.task_decision("get", p, task_id, task, {})[0] if by_pdp else self.owner_rule(p, task)
            if readable and task is not None:
                raise HttpError(HTTPStatus.FORBIDDEN, "forbidden")
            raise HttpError(HTTPStatus.NOT_FOUND, "not found")
        if task is None:
            raise HttpError(HTTPStatus.NOT_FOUND, "not found")
        task["state"] = "CANCELED"
        return {}

    def list(self, p: Principal, page_size: int, page_token: str | None, view: str) -> dict[str, Any]:
        """ListTasks with keyset paging, in the list scope (spec section 3.5).

        By default, and after a failed decision with ``open``, the scope is
        ``own``; switched on, it comes from the answer, and a deny is ``none``
        (an empty list, without reading the store).

        Args:
            p: The caller.
            page_size: Maximum page size.
            page_token: Cursor from the previous page.
            view: The view.

        Returns:
            The page.

        Raises:
            HttpError: 400 on a bad page token.
            DecisionServiceError: On a failed decision when failing closed (503).
        """
        scope = "own"
        if self.switched_on("list"):
            try:
                scope = list_scope(self.ask(p, "ListTasks", {"type": "tes_task_set", "id": "own"}, {"view": view}))
            except DecisionServiceError:
                self.fall_back("list")
        if scope == "none":
            return {"tasks": []}
        # Page tokens are bound to the list scope (spec section 3.5): a keyset
        # cursor from one scope would skip tasks of a wider one.
        token_scope, _, position = (page_token or "").partition(".")
        if page_token and token_scope != scope:
            raise HttpError(HTTPStatus.BAD_REQUEST, "page token of another list scope")
        try:
            after = int(position) if page_token else -1
        except ValueError as exc:
            raise HttpError(HTTPStatus.BAD_REQUEST, "bad page token") from exc
        with self.store.lock:
            ids = sorted(self.store.tasks, key=self.store.order.__getitem__)
            rows = [
                t
                for t in (self.store.tasks[i] for i in ids)
                if self.store.order[t["id"]] > after and self._in_scope(scope, p, t)
            ]
        page = rows[:page_size]
        result: dict[str, Any] = {"tasks": [self._render(t, view) for t in page]}
        if len(rows) > page_size:
            result["next_page_token"] = f"{scope}.{self.store.order[page[-1]['id']]}"
        return result

    @staticmethod
    def _render(task: dict[str, Any], view: str) -> dict[str, Any]:
        if view == "MINIMAL":
            return {"id": task["id"], "state": task["state"]}
        return {k: v for k, v in task.items() if not k.startswith("_")}


def make_handler(hook: Hook, auth: OidcAuth) -> type[BaseHTTPRequestHandler]:
    """Build the HTTP handler.

    Args:
        hook: The hook.
        auth: The OIDC AuthN.

    Returns:
        The handler class.
    """

    class Handler(BaseHTTPRequestHandler):
        """Mock TES handler."""

        timeout = SOCKET_TIMEOUT

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            """Silence access logs.

            Args:
                format: The format string.
                *args: The format arguments.
            """

        def _send(self, status: int, body: Any) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _length(self) -> int | None:
            """Return the declared body length, or answer an error.

            Returns:
                The length (0 without ``Content-Length``), or ``None`` after
                answering 411 (chunked), 400 (not a non-negative integer) or
                413 (over ``MAX_BODY_BYTES``), with the body unread and the
                connection closed.
            """
            status, message = None, ""
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
            except ValueError:
                length = -1
            if self.headers.get("Transfer-Encoding"):
                status, message = HTTPStatus.LENGTH_REQUIRED, "Content-Length required"
            elif length < 0:
                status, message = HTTPStatus.BAD_REQUEST, "bad length"
            elif length > MAX_BODY_BYTES:
                status, message = HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body too large"
            if status is None:
                return length
            self.close_connection = True
            self._send(status, {"message": message})
            return None

        def _run(self, fn: Callable[[], Any]) -> None:
            try:
                self._send(HTTPStatus.OK, fn())
            except HttpError as exc:
                self._send(exc.status, {"message": str(exc)})

        def do_GET(self) -> None:
            """Serve service-info, GetTask and ListTasks."""
            url = urllib.parse.urlsplit(self.path)
            query = dict(urllib.parse.parse_qsl(url.query))
            view = query.get("view", "MINIMAL")
            if url.path == f"{PREFIX}/service-info":
                self._send(HTTPStatus.OK, {"id": hook.settings.service_id, "name": "mock TES"})
                return

            def run() -> Any:
                p = auth.authenticate(self.headers.get("Authorization"))
                if url.path == f"{PREFIX}/tasks":
                    return hook.list(p, int(query.get("page_size", "256")), query.get("page_token"), view)
                if url.path.startswith(f"{PREFIX}/tasks/"):
                    return hook.get(p, url.path.removeprefix(f"{PREFIX}/tasks/"), view)
                raise HttpError(HTTPStatus.NOT_FOUND, "not found")

            self._run(run)

        def do_POST(self) -> None:
            """Serve CreateTask and CancelTask."""
            path = urllib.parse.urlsplit(self.path).path
            length = self._length()
            if length is None:
                return
            # `_length()` rejected longer bodies; `min()` bounds the read here too,
            # where the semgrep rule request-body-unbounded can see it
            raw = self.rfile.read(min(length, MAX_BODY_BYTES)) if length > 0 else b"{}"

            def run() -> Any:
                p = auth.authenticate(self.headers.get("Authorization"))
                if path == f"{PREFIX}/tasks":
                    body = json.loads(raw)
                    if not isinstance(body, dict):
                        raise HttpError(HTTPStatus.BAD_REQUEST, "bad task")
                    return hook.create(p, body)
                if path.startswith(f"{PREFIX}/tasks/") and path.endswith(":cancel"):
                    return hook.cancel(p, path.removeprefix(f"{PREFIX}/tasks/").removesuffix(":cancel"))
                raise HttpError(HTTPStatus.NOT_FOUND, "not found")

            self._run(run)

    return Handler


def start(settings: Settings) -> tuple[ThreadingHTTPServer, str]:
    """Start a mock TES on a free loopback port in a background thread.

    Args:
        settings: The hook settings.

    Returns:
        The server and its base URL (with ``/ga4gh/tes/v1``).

    Raises:
        ValueError: If the settings fail the startup checks.
    """
    check_settings(settings)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(Hook(settings, Store()), OidcAuth(settings)))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}{PREFIX}"

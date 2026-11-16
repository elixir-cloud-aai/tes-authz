"""Minimal in-memory TES with the AuthZ hook of spec draft 3, section 6.

Test-only. It exists to exercise the harness (stub, golden comparison,
engines) end to end before a real TES has the hook, and as executable
pseudo-code of the hook. It is not a TES implementation:

* Tokens are NOT validated: ``Bearer mock.<base64url(JSON claims)>`` is
  taken at face value. Real TESes validate OIDC tokens (phase 2 adds a mock
  OIDC issuer to the harness for them).
* No userinfo, no executors, no backend; tasks stay ``QUEUED``.
"""

from __future__ import annotations

import base64
import binascii
import json
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shims"))

from common import strip_url

PREFIX = "/ga4gh/tes/v1"
PROFILE = "tes-authzen/1"


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
    """

    pdp_url: str | None = None
    timeout: float = 2.0
    claims: tuple[str, ...] = ()
    rule_name: str | None = None
    rule_values: tuple[str, ...] = ()
    rule_prefixes: tuple[str, ...] = ()
    service_id: str = "tes-authz-test"


@dataclass
class Principal:
    """The authenticated caller.

    Attributes:
        claims: The (unvalidated, test-only) token claims.
    """

    claims: dict[str, Any]

    @property
    def owner_id(self) -> str:
        """The owner ID (single issuer: ``sub``)."""
        return str(self.claims["sub"])


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


def lookup(claims: dict[str, Any], name: str) -> Any:
    """Look a claim up: exact top-level name, then dotted path.

    Args:
        claims: The token claims.
        name: The claim name.

    Returns:
        The value, or ``_MISSING``.
    """
    if name in claims:
        return claims[name]
    node: Any = claims
    for part in name.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


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
            value = lookup(c, name)
            if value is not _MISSING:
                claims[name] = value
        props["claims"] = claims
        return {"type": "user", "id": p.owner_id, "properties": props}

    def gate(self, p: Principal) -> None:
        """Apply the built-in claim rule.

        Args:
            p: The caller.

        Raises:
            HttpError: 403 if the rule is set and fails.
        """
        if not self.settings.rule_name:
            return
        value = lookup(p.claims, self.settings.rule_name)
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise HttpError(HTTPStatus.FORBIDDEN, "forbidden")
        if any(
            x in self.settings.rule_values or any(x.startswith(q) for q in self.settings.rule_prefixes) for x in value
        ):
            return
        raise HttpError(HTTPStatus.FORBIDDEN, "forbidden")

    def ask(self, p: Principal, action: str, resource: dict[str, Any], aprops: dict[str, Any] | None = None) -> bool:
        """Ask the decision service.

        Args:
            p: The caller.
            action: The action name.
            resource: The resource.
            aprops: Action properties.

        Returns:
            The decision.

        Raises:
            HttpError: 503 on any failure.
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
                    raise HttpError(HTTPStatus.SERVICE_UNAVAILABLE, "decision service unavailable")
                answer = json.loads(response.read())
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise HttpError(HTTPStatus.SERVICE_UNAVAILABLE, "decision service unavailable") from exc
        if not isinstance(answer, dict) or not isinstance(answer.get("decision"), bool):
            raise HttpError(HTTPStatus.SERVICE_UNAVAILABLE, "decision service unavailable")
        return answer["decision"] is True

    def _meta(self, task_id: str) -> dict[str, Any] | None:
        task = self.store.tasks.get(task_id)
        if task is None:
            return None
        return {"owner": task["_owner"], "state": task["state"], "tags": task.get("tags", {})}

    @staticmethod
    def _res(task_id: str, meta: dict[str, Any] | None) -> dict[str, Any]:
        return {"type": "tes_task", "id": task_id, "properties": meta or {}}

    def create(self, p: Principal, task: dict[str, Any]) -> dict[str, Any]:
        """CreateTask.

        Args:
            p: The caller.
            task: The submitted task.

        Returns:
            ``{"id": ...}``.

        Raises:
            HttpError: On deny or failure.
        """
        self.gate(p)
        executors = task.get("executors")
        if not isinstance(executors, list) or not all(
            isinstance(ex, dict) and isinstance(ex.get("image"), str) for ex in executors
        ):
            raise HttpError(HTTPStatus.BAD_REQUEST, "executors must be a list of objects with an image")
        for key in ("id", "state", "creation_time", "logs"):
            task.pop(key, None)
        if self.settings.pdp_url and not self.ask(
            p, "CreateTask", {"type": "tes_task_set", "id": "own", "properties": {"task": project(task)}}
        ):
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
            HttpError: On deny, absence or failure.
        """
        self.gate(p)
        meta = self._meta(task_id)
        if self.settings.pdp_url:
            allow = self.ask(p, "GetTask", self._res(task_id, meta), {"view": view})
        else:
            allow = meta is not None and meta["owner"] == p.owner_id
        if meta is None or not allow:
            raise HttpError(HTTPStatus.NOT_FOUND, "not found")
        return self._render(self.store.tasks[task_id], view)

    def cancel(self, p: Principal, task_id: str) -> dict[str, Any]:
        """CancelTask.

        Args:
            p: The caller.
            task_id: The task ID.

        Returns:
            ``{}``.

        Raises:
            HttpError: On deny, absence or failure.
        """
        self.gate(p)
        meta = self._meta(task_id)
        if self.settings.pdp_url:
            allow = self.ask(p, "CancelTask", self._res(task_id, meta))
        else:
            allow = meta is not None and meta["owner"] == p.owner_id
        if meta is None:
            raise HttpError(HTTPStatus.NOT_FOUND, "not found")
        if not allow:
            readable = bool(self.settings.pdp_url) and self.ask(p, "GetTask", self._res(task_id, meta))
            raise HttpError(HTTPStatus.FORBIDDEN if readable else HTTPStatus.NOT_FOUND, "forbidden")
        self.store.tasks[task_id]["state"] = "CANCELED"
        return {}

    def list(self, p: Principal, page_size: int, page_token: str | None, view: str) -> dict[str, Any]:
        """ListTasks with keyset paging.

        Args:
            p: The caller.
            page_size: Maximum page size.
            page_token: Cursor from the previous page.
            view: The view.

        Returns:
            The page.

        Raises:
            HttpError: On deny or failure.
        """
        self.gate(p)
        if not self.settings.pdp_url:
            own_only = True
        else:
            if self.ask(p, "ListTasks", {"type": "tes_task_set", "id": "all"}, {"view": view}):
                own_only = False
            elif self.ask(p, "ListTasks", {"type": "tes_task_set", "id": "own"}, {"view": view}):
                own_only = True
            else:
                raise HttpError(HTTPStatus.FORBIDDEN, "forbidden")
        try:
            after = int(page_token) if page_token else -1
        except ValueError as exc:
            raise HttpError(HTTPStatus.BAD_REQUEST, "bad page token") from exc
        with self.store.lock:
            ids = sorted(self.store.tasks, key=self.store.order.__getitem__)
            rows = [
                t
                for t in (self.store.tasks[i] for i in ids)
                if self.store.order[t["id"]] > after and (not own_only or t["_owner"] == p.owner_id)
            ]
        page = rows[:page_size]
        result: dict[str, Any] = {"tasks": [self._render(t, view) for t in page]}
        if len(rows) > page_size:
            result["next_page_token"] = str(self.store.order[page[-1]["id"]])
        return result

    @staticmethod
    def _render(task: dict[str, Any], view: str) -> dict[str, Any]:
        if view == "MINIMAL":
            return {"id": task["id"], "state": task["state"]}
        return {k: v for k, v in task.items() if not k.startswith("_")}


def principal_from(header: str | None) -> Principal:
    """Decode the test-only bearer token.

    Args:
        header: The ``Authorization`` header.

    Returns:
        The caller.

    Raises:
        HttpError: 401 if the token is missing or malformed.
    """
    if not header or not header.startswith("Bearer mock."):
        raise HttpError(HTTPStatus.UNAUTHORIZED, "unauthorized")
    raw = header.removeprefix("Bearer mock.")
    try:
        claims = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except (ValueError, binascii.Error) as exc:
        raise HttpError(HTTPStatus.UNAUTHORIZED, "unauthorized") from exc
    if not isinstance(claims, dict) or not isinstance(claims.get("sub"), str):
        raise HttpError(HTTPStatus.UNAUTHORIZED, "unauthorized")
    return Principal(claims)


def make_handler(hook: Hook) -> type[BaseHTTPRequestHandler]:
    """Build the HTTP handler.

    Args:
        hook: The hook.

    Returns:
        The handler class.
    """

    class Handler(BaseHTTPRequestHandler):
        """Mock TES handler."""

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
                p = principal_from(self.headers.get("Authorization"))
                if url.path == f"{PREFIX}/tasks":
                    return hook.list(p, int(query.get("page_size", "256")), query.get("page_token"), view)
                if url.path.startswith(f"{PREFIX}/tasks/"):
                    return hook.get(p, url.path.removeprefix(f"{PREFIX}/tasks/"), view)
                raise HttpError(HTTPStatus.NOT_FOUND, "not found")

            self._run(run)

        def do_POST(self) -> None:
            """Serve CreateTask and CancelTask."""
            path = urllib.parse.urlsplit(self.path).path
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length else b"{}"

            def run() -> Any:
                p = principal_from(self.headers.get("Authorization"))
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
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(Hook(settings, Store())))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}{PREFIX}"

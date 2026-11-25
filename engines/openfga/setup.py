"""Load the reference policy into OpenFGA: store, model and tuples.

The tuples are generated from the same data file as the OPA policy
(``config/reference-policy.json``), so both engines are configured from one
place. The store and model IDs go to a state file that the shim reads.

Settings (environment):
    FGA_URL: Base URL of OpenFGA (default ``http://openfga:8080``).
    POLICY_FILE: The policy data file (default ``/config/reference-policy.json``).
    MODEL_FILE: The model in API JSON (default ``/engine/model.json``).
    FGA_STATE_FILE: Where to write the IDs (default ``/state/openfga.json``).
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, os.environ.get("SHIMS_DIR", "/shims"))

from common import UpstreamError, encode_id, post_json
from openfga_shim import task_set_object, to_openfga

PLAIN_ID = re.compile(r"[!-~]+")
"""A service client's ``iss`` or ``client_id``: printable ASCII without spaces (``!`` to ``~``).

Same check as ``plain_id`` in the OPA policy. It also keeps the ``listed_client``
pairs (``<iss> <client_id>``, one space) unambiguous.
"""

FGA_URL = os.environ.get("FGA_URL", "http://openfga:8080").rstrip("/")
MAX_LIST_ITEMS = int(os.environ.get("SHIM_MAX_LIST_ITEMS", "1024"))
ITEM_LENGTH = int(os.environ.get("SELF_CHECK_ITEM_LENGTH", "200"))
SELF_CHECK_PROFILE = "tes-authzen/3"
"""Profile of the self-check requests (one of ``common.PROFILES``)."""


def check_policy(policy: dict[str, Any]) -> None:
    """Reject configuration the OpenFGA conditions would evaluate differently from OPA.

    Args:
        policy: The decoded policy data file.

    Raises:
        SystemExit: If a prefix is empty (CEL ``"".startsWith("")`` would
            match the shim's empty-image sentinel), if the file still has
            ``admins`` (removed: nobody reaches other owners' tasks, so an
            admin group would silently grant nothing), or if
            ``service_clients`` is malformed (OPA denies every request then).
    """
    if "admins" in policy:
        raise SystemExit("the policy data file has 'admins': the reference policy is owner only, remove it")
    clients = policy.get("service_clients", [])
    if not isinstance(clients, list) or not all(
        isinstance(c, dict)
        and set(c) == {"iss", "client_id"}
        and all(isinstance(c[k], str) and PLAIN_ID.fullmatch(c[k]) for k in ("iss", "client_id"))
        for c in clients
    ):
        raise SystemExit(
            "malformed 'service_clients' in the policy data file: a list of {iss, client_id}, "
            "both printable ASCII strings without spaces"
        )
    prefixes = [*policy["members"]["prefixes"], *policy["image_prefixes"]]
    if any(not isinstance(p, str) or not p for p in prefixes):
        raise SystemExit("empty or non-string prefix in the policy data file")


def worst_cases(policy: dict[str, Any], service: str) -> list[dict[str, Any]]:
    """Build requests that make every condition walk the longest lists.

    Args:
        policy: The decoded policy data file.
        service: A configured service ID.

    Returns:
        Profile requests (non-matching entitlements, images matching only the
        last prefix; ``CreateTask`` once as a member and once as a caller
        that is neither a member nor a listed client), each at
        ``MAX_LIST_ITEMS`` items of ``ITEM_LENGTH``.
    """
    filler = "x" * ITEM_LENGTH
    entitlements = [f"urn:self-check:{i}:{filler}" for i in range(MAX_LIST_ITEMS)]
    last = policy["image_prefixes"][-1] if policy["image_prefixes"] else "img/"
    member = (policy["members"]["values"] + policy["members"]["prefixes"] or ["none"])[-1]
    claim = policy["entitlement_claim"]
    context = {"tes": {"profile": SELF_CHECK_PROFILE, "service_id": service}}

    listed = {(c["iss"], c["client_id"]) for c in policy.get("service_clients", [])}
    client = next(f"self-check-{i}" for i in range(len(listed) + 1) if ("self-check", f"self-check-{i}") not in listed)

    def req(action: str, rtype: str, rid: str, ents: list[str], props: dict[str, Any]) -> dict[str, Any]:
        # A client that isn't listed, so listed_client walks the whole list too
        subject = {"iss": "self-check", "sub": client, "client_id": client, "claims": {claim: ents}}
        return {
            "subject": {"type": "user", "id": "self-check", "properties": subject},
            "action": {"name": action},
            "resource": {"type": rtype, "id": rid, "properties": props},
            "context": context,
        }

    task = {"executors": [{"image": last + filler} for _ in range(MAX_LIST_ITEMS)]}
    return [
        req("ListTasks", "tes_task_set", "own", entitlements, {}),
        req("CreateTask", "tes_task_set", "own", [*entitlements[:-1], member], {"task": task}),
        # Neither a member nor a listed client: both branches of may_create are evaluated
        req("CreateTask", "tes_task_set", "own", entitlements, {"task": task}),
    ]


def self_check(policy: dict[str, Any], store_id: str, model_id: str) -> None:
    """Evaluate the worst cases, so a too-small CEL cost budget fails at setup.

    Args:
        policy: The decoded policy data file.
        store_id: The store.
        model_id: The model.

    Raises:
        SystemExit: If OpenFGA errors on a worst case.
    """
    url = f"{FGA_URL}/stores/{store_id}/access/v1/evaluation"
    claims = {"entitlements": policy["entitlement_claim"]}
    for service in policy["services"]:
        for case in worst_cases(policy, service):
            try:
                post_json(url, to_openfga(case, claims), 10, {"Openfga-Authorization-Model-Id": model_id})
            except UpstreamError as exc:
                raise SystemExit(
                    f"self-check failed for {case['action']['name']} with {MAX_LIST_ITEMS} items: {exc}; "
                    "raise OPENFGA_MAX_CONDITION_EVALUATION_COST or lower SHIM_MAX_LIST_ITEMS"
                ) from exc


def tuples_for(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate the tuples of the reference policy.

    Owner only: the entitlement, or a listed service client
    (``listed_client``), is needed only to create; ``GetTask`` and
    ``CancelTask`` need ownership alone, and ``ListTasks`` on ``own`` is open
    to every caller (the TES lists only their tasks). No tuple on a
    service's ``all`` set, so ``ListTasks`` on it is always denied, and no
    admin tuple on ``tes_service``.

    Args:
        policy: The decoded policy data file.

    Returns:
        The tuple keys to write.
    """
    members = {"allowed_values": policy["members"]["values"], "allowed_prefixes": policy["members"]["prefixes"]}
    images = {"allowed_image_prefixes": policy["image_prefixes"]}
    clients = {"allowed_clients": [f"{c['iss']} {c['client_id']}" for c in policy.get("service_clients", [])]}
    tuples: list[dict[str, Any]] = []

    def add(obj: str, relation: str, condition: str | None, context: dict[str, Any] | None = None) -> None:
        key: dict[str, Any] = {"user": "user:*", "relation": relation, "object": obj}
        if condition is not None:
            key["condition"] = {"name": condition} if context is None else {"name": condition, "context": context}
        tuples.append(key)

    for service in policy["services"]:
        own = "tes_task_set:" + task_set_object(service, "own")
        svc = "tes_service:" + encode_id(service)
        add(own, "creator", "entitled", members)
        add(own, "service_client", "listed_client", clients)
        add(own, "image_ok", "images_allowed", images)
        add(own, "lister", None)
        add(svc, "owner", "is_owner")
    return tuples


def call(method: str, path: str, body: Any = None) -> Any:
    """Call the OpenFGA HTTP API.

    Args:
        method: HTTP method.
        path: Path below the base URL.
        body: JSON body, if any.

    Returns:
        The decoded JSON answer.
    """
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(FGA_URL + path, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read() or b"{}")


def wait_ready(timeout: float = 60.0) -> None:
    """Wait until OpenFGA answers its health check.

    Args:
        timeout: Seconds to wait.

    Raises:
        TimeoutError: If OpenFGA is not ready in time.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(FGA_URL + "/healthz", timeout=2):
                return
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    raise TimeoutError("OpenFGA did not become ready")


def main() -> None:
    """Create the store, write model and tuples, and record the IDs."""
    policy = json.loads(Path(os.environ.get("POLICY_FILE", "/config/reference-policy.json")).read_text())
    model = json.loads(Path(os.environ.get("MODEL_FILE", "/engine/model.json")).read_text())
    check_policy(policy)
    wait_ready()
    store_id = call("POST", "/stores", {"name": "tes-authz-reference"})["id"]
    model_id = call("POST", f"/stores/{store_id}/authorization-models", model)["authorization_model_id"]
    tuples = tuples_for(policy)
    for start in range(0, len(tuples), 100):
        call(
            "POST",
            f"/stores/{store_id}/write",
            {"writes": {"tuple_keys": tuples[start : start + 100]}, "authorization_model_id": model_id},
        )
    self_check(policy, store_id, model_id)
    state = Path(os.environ.get("FGA_STATE_FILE", "/state/openfga.json"))
    state.parent.mkdir(parents=True, exist_ok=True)
    tmp = state.with_suffix(".tmp")
    claims = {"entitlements": policy["entitlement_claim"]}
    tmp.write_text(json.dumps({"store_id": store_id, "model_id": model_id, "claims": claims}))
    tmp.replace(state)
    print(f"store={store_id} model={model_id} tuples={len(tuples)}")


if __name__ == "__main__":
    main()

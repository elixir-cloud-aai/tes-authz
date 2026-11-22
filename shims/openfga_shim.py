"""Thin AuthZEN shim for OpenFGA (spec draft 3, section 7).

OpenFGA's experimental AuthZEN Evaluation is a Check: the action name is a
relation, the resource is an object that needs a stored tuple, and
properties reach conditions as ``subject_*``/``resource_*`` context. The
shim rewrites a profile request into a request OpenFGA can answer:

* ``tes_task:<id>`` becomes ``tes_service:<service>``; per-task ownership is
  a condition on a ``user:*`` tuple (``resource_owner == subject_id``).
* ``tes_task_set:<own|all>`` becomes ``tes_task_set:<service>/<own|all>``.
* The subject ID becomes ``user:h-<sha256>`` because OpenFGA rejects
  subject IDs with ``:``, ``#``, ``@``, whitespace or more than 500
  characters (``https://iss|sub`` owners would fail); the real ID travels as
  the ``subject_id`` condition parameter.
* Every condition parameter is always present (review 2, finding 3):
  ``subject_id``, ``resource_owner`` (empty string when the task has no
  owner or does not exist), ``resource_images`` and one list parameter per
  mapped claim (empty when the claim is missing), and ``subject_delegated``
  (whether ``subject.properties`` has an ``actor``, ``tes-authzen/2``).
  OpenFGA answers a missing parameter with HTTP 400, which would turn a
  missing task into 503.

No policy lives here: which entitlements count is in the tuples.

Settings (environment):
    FGA_URL: Base URL of OpenFGA (default ``http://openfga:8080``).
    FGA_STATE_FILE: JSON file with ``store_id`` and ``model_id`` written by
        the setup job (default ``/state/openfga.json``).
    FGA_STORE_ID / FGA_MODEL_ID: Override the state file.
    FGA_CLAIMS: Comma-separated ``param=claim`` pairs; each claim from
        ``subject.properties.claims`` is passed as list parameter
        ``subject_<param>``. Default: taken from the state file, where the
        setup job writes ``entitlements=<entitlement_claim>`` from the
        policy data file; a disagreeing value refuses to start.
    SHIM_MAX_LIST_ITEMS: Largest claim or executor list (default 1024).
    SHIM_PORT: Port to listen on (default ``8080``).
    SHIM_TIMEOUT: Timeout for OpenFGA calls in seconds (default ``1.5``).
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from common import UpstreamError, encode_id, hash_id, post_json, serve, string_list

FGA_URL = os.environ.get("FGA_URL", "http://openfga:8080").rstrip("/")
TIMEOUT = float(os.environ.get("SHIM_TIMEOUT", "1.5"))
MAX_LIST_ITEMS = int(os.environ.get("SHIM_MAX_LIST_ITEMS", "1024"))
"""Largest claim or executor list passed to OpenFGA.

OpenFGA bounds the CEL cost of a condition (``OPENFGA_MAX_CONDITION_EVALUATION_COST``);
compose.yaml raises it so that lists up to this size are evaluated. Longer lists
fail the request (502, so 503 at the TES) instead of risking a cost error.
"""


def parse_claim_map(spec: str) -> dict[str, str]:
    """Parse the ``FGA_CLAIMS`` setting.

    Args:
        spec: Comma-separated ``param=claim`` pairs.

    Returns:
        A map from condition parameter suffix to claim name.

    Raises:
        ValueError: If a pair is malformed.
    """
    mapping: dict[str, str] = {}
    for pair in filter(None, (part.strip() for part in spec.split(","))):
        param, sep, claim = pair.partition("=")
        if not sep or not param.isidentifier() or not claim or param in {"id", "delegated"}:
            raise ValueError(f"bad FGA_CLAIMS entry: {pair!r}")
        mapping[param] = claim
    return mapping


def task_set_object(service_id: str, set_id: str) -> str:
    """Return the OpenFGA object ID of a task set of one service.

    Args:
        service_id: The TES service-info ID.
        set_id: ``own`` or ``all``.

    Returns:
        The object ID (without the type).
    """
    return f"{encode_id(service_id)}/{set_id}"


def to_openfga(req: dict[str, Any], claim_map: dict[str, str]) -> dict[str, Any]:
    """Rewrite a validated profile request into an OpenFGA AuthZEN request.

    Args:
        req: The validated AuthZEN request (``tes-authzen/1`` or ``/2``).
        claim_map: Condition parameter suffix to claim name.

    Returns:
        The request for OpenFGA's store-scoped evaluation endpoint.
    """
    subject = req["subject"]
    properties = subject.get("properties", {})
    claims = properties.get("claims", {})
    if not isinstance(claims, dict):
        claims = {}
    subject_props: dict[str, Any] = {"id": subject["id"]}
    for param, claim in claim_map.items():
        subject_props[param] = string_list(claims.get(claim))
    # A delegated token (RFC 8693 actor); the model decides what that means.
    subject_props["delegated"] = "actor" in properties

    resource = req["resource"]
    props = resource.get("properties", {})
    owner = props.get("owner")
    task = props.get("task")
    if isinstance(task, dict) and isinstance(task.get("executors"), list):
        executors: list[Any] = task["executors"]
        images = [ex["image"] if isinstance(ex, dict) and isinstance(ex.get("image"), str) else "" for ex in executors]
    else:
        # Missing or malformed executors: one empty image, which no allowlist
        # prefix matches (OPA denies these as well when an allowlist is set).
        images = [""]
    resource_props = {"owner": owner if isinstance(owner, str) else "", "images": images}

    service_id = req["context"]["tes"]["service_id"]
    # Maps the resource type to an OpenFGA object type; decides nothing
    # ast-grep-ignore: shim-policy-decision
    if resource["type"] == "tes_task":
        target: dict[str, Any] = {"type": "tes_service", "id": encode_id(service_id)}
    else:
        target = {"type": "tes_task_set", "id": task_set_object(service_id, resource["id"])}
    target["properties"] = resource_props
    return {
        "subject": {"type": "user", "id": hash_id(subject["id"]), "properties": subject_props},
        "action": {"name": req["action"]["name"]},
        "resource": target,
    }


class OpenFgaShim:
    """Decision function bound to one OpenFGA store."""

    def __init__(self, store_id: str, model_id: str | None, claim_map: dict[str, str]) -> None:
        """Bind the shim to a store.

        Args:
            store_id: The OpenFGA store ID.
            model_id: The authorization model ID to pin, if known.
            claim_map: Condition parameter suffix to claim name.
        """
        self.url = f"{FGA_URL}/stores/{store_id}/access/v1/evaluation"
        self.model_id = model_id
        self.claim_map = claim_map

    def decide(self, req: dict[str, Any], headers: dict[str, str]) -> bool:
        """Ask OpenFGA for the decision on one request.

        Args:
            req: The validated AuthZEN request.
            headers: Headers to forward (``X-Request-ID``).

        Returns:
            The decision; only a boolean ``true`` allows.

        Raises:
            UpstreamError: If OpenFGA fails or answers without a boolean.
        """
        mapped = to_openfga(req, self.claim_map)
        lists = [mapped["resource"]["properties"]["images"]]
        lists += [mapped["subject"]["properties"][param] for param in self.claim_map]
        if any(len(items) > MAX_LIST_ITEMS for items in lists):
            raise UpstreamError(f"request has more than {MAX_LIST_ITEMS} claim values or executors")
        extra = dict(headers)
        if self.model_id:
            extra["Openfga-Authorization-Model-Id"] = self.model_id
        answer = post_json(self.url, mapped, TIMEOUT, extra)
        decision = answer.get("decision") if isinstance(answer, dict) else None
        if not isinstance(decision, bool):
            raise UpstreamError("OpenFGA answer has no boolean decision")
        return decision


def load_state(path: str, wait_seconds: float = 60.0) -> dict[str, Any]:
    """Read the store and model IDs written by the setup job.

    Args:
        path: The state file.
        wait_seconds: How long to wait for the file to appear.

    Returns:
        The decoded state.

    Raises:
        FileNotFoundError: If the file does not appear in time.
    """
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            with open(path, encoding="utf-8") as handle:
                state: dict[str, Any] = json.load(handle)
                return state
        except FileNotFoundError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)


def main() -> None:
    """Run the shim."""
    logging.basicConfig(level=os.environ.get("SHIM_LOG_LEVEL", "INFO"))
    store_id = os.environ.get("FGA_STORE_ID")
    model_id = os.environ.get("FGA_MODEL_ID")
    state_path = os.environ.get("FGA_STATE_FILE", "/state/openfga.json")
    state_claims: dict[str, str] | None = None
    if not store_id or os.path.exists(state_path):
        state = load_state(state_path)
        store_id = store_id or state["store_id"]
        model_id = model_id or state.get("model_id")
        state_claims = state.get("claims")
    env_claims = os.environ.get("FGA_CLAIMS")
    claim_map = parse_claim_map(env_claims) if env_claims else state_claims
    if not claim_map:
        raise SystemExit("no claim map: set FGA_CLAIMS (FGA_STORE_ID without a state file) or run the setup job")
    if state_claims is not None and claim_map != state_claims:
        raise SystemExit(f"FGA_CLAIMS {claim_map} disagrees with the policy data file {state_claims}")
    shim = OpenFgaShim(store_id, model_id, claim_map)
    base = os.environ.get("SHIM_BASE_URL", "http://localhost:8080")
    serve(
        int(os.environ.get("SHIM_PORT", "8080")),
        shim.decide,
        {"policy_decision_point": base, "access_evaluation_endpoint": base + "/access/v1/evaluation"},
    )


if __name__ == "__main__":
    main()

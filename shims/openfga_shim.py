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
  mapped claim (empty when the claim is missing). OpenFGA answers a missing
  parameter with HTTP 400, which would turn a missing task into 503.

No policy lives here: which entitlements count is in the tuples.

Settings (environment):
    FGA_URL: Base URL of OpenFGA (default ``http://openfga:8080``).
    FGA_STATE_FILE: JSON file with ``store_id`` and ``model_id`` written by
        the setup job (default ``/state/openfga.json``).
    FGA_STORE_ID / FGA_MODEL_ID: Override the state file.
    FGA_CLAIMS: Comma-separated ``param=claim`` pairs; each claim from
        ``subject.properties.claims`` is passed as list parameter
        ``subject_<param>`` (default ``entitlements=eduperson_entitlement``).
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
        if not sep or not param.isidentifier() or not claim:
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
        req: The validated AuthZEN request (``tes-authzen/1``).
        claim_map: Condition parameter suffix to claim name.

    Returns:
        The request for OpenFGA's store-scoped evaluation endpoint.
    """
    subject = req["subject"]
    claims = subject.get("properties", {}).get("claims", {})
    if not isinstance(claims, dict):
        claims = {}
    subject_props: dict[str, Any] = {"id": subject["id"]}
    for param, claim in claim_map.items():
        subject_props[param] = string_list(claims.get(claim))

    resource = req["resource"]
    props = resource.get("properties", {})
    owner = props.get("owner")
    task = props.get("task") if isinstance(props.get("task"), dict) else {}
    executors = task.get("executors") if isinstance(task.get("executors"), list) else []
    images = [
        ex["image"] if isinstance(ex, dict) and isinstance(ex.get("image"), str) else ""
        for ex in executors
    ]
    resource_props = {"owner": owner if isinstance(owner, str) else "", "images": images}

    service_id = req["context"]["tes"]["service_id"]
    if resource["type"] == "tes_task":
        target = {"type": "tes_service", "id": encode_id(service_id)}
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
        extra = dict(headers)
        if self.model_id:
            extra["Openfga-Authorization-Model-Id"] = self.model_id
        answer = post_json(self.url, to_openfga(req, self.claim_map), TIMEOUT, extra)
        decision = answer.get("decision") if isinstance(answer, dict) else None
        if not isinstance(decision, bool):
            raise UpstreamError("OpenFGA answer has no boolean decision")
        return decision


def load_state(path: str, wait_seconds: float = 60.0) -> dict[str, str]:
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
                state: dict[str, str] = json.load(handle)
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
    if not store_id:
        state = load_state(os.environ.get("FGA_STATE_FILE", "/state/openfga.json"))
        store_id, model_id = state["store_id"], state.get("model_id")
    claim_map = parse_claim_map(os.environ.get("FGA_CLAIMS", "entitlements=eduperson_entitlement"))
    shim = OpenFgaShim(store_id, model_id, claim_map)
    base = os.environ.get("SHIM_BASE_URL", "http://localhost:8080")
    serve(
        int(os.environ.get("SHIM_PORT", "8080")),
        shim.decide,
        {"policy_decision_point": base, "access_evaluation_endpoint": base + "/access/v1/evaluation"},
    )


if __name__ == "__main__":
    main()

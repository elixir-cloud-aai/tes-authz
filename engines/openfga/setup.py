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
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, os.environ.get("SHIMS_DIR", "/shims"))

from common import encode_id
from openfga_shim import task_set_object

FGA_URL = os.environ.get("FGA_URL", "http://openfga:8080").rstrip("/")


def tuples_for(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate the tuples of the reference policy.

    Args:
        policy: The decoded policy data file.

    Returns:
        The tuple keys to write.
    """
    members = {"allowed_values": policy["members"]["values"], "allowed_prefixes": policy["members"]["prefixes"]}
    admins = {"allowed_values": policy["admins"]["values"], "allowed_prefixes": policy["admins"]["prefixes"]}
    images = {"allowed_image_prefixes": policy["image_prefixes"]}
    tuples: list[dict[str, Any]] = []

    def add(obj: str, relation: str, condition: str, context: dict[str, Any] | None) -> None:
        cond: dict[str, Any] = {"name": condition}
        if context is not None:
            cond["context"] = context
        tuples.append({"user": "user:*", "relation": relation, "object": obj, "condition": cond})

    for service in policy["services"]:
        own = "tes_task_set:" + task_set_object(service, "own")
        all_ = "tes_task_set:" + task_set_object(service, "all")
        svc = "tes_service:" + encode_id(service)
        add(own, "creator", "entitled", members)
        add(own, "image_ok", "images_allowed", images)
        add(own, "lister", "entitled", members)
        add(all_, "lister", "entitled", admins)
        add(svc, "owner", "is_owner", None)
        add(svc, "admin", "entitled", admins)
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
    state = Path(os.environ.get("FGA_STATE_FILE", "/state/openfga.json"))
    state.parent.mkdir(parents=True, exist_ok=True)
    tmp = state.with_suffix(".tmp")
    tmp.write_text(json.dumps({"store_id": store_id, "model_id": model_id}))
    tmp.replace(state)
    print(f"store={store_id} model={model_id} tuples={len(tuples)}")


if __name__ == "__main__":
    main()

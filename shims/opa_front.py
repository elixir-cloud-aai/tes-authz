"""Thin AuthZEN front for OPA.

OPA has no AuthZEN endpoint of its own (the community ``opa-authzen-plugin``
needs a custom OPA build), so this front serves ``/access/v1/evaluation``,
passes the request unchanged as ``input`` to OPA's Data API and returns the
policy's boolean as ``{"decision": ...}``. All policy is in Rego.

Settings (environment):
    OPA_URL: Base URL of OPA (default ``http://opa:8181``).
    OPA_DECISION_PATH: Data API path of the decision (default ``tes/authz/allow``).
    SHIM_PORT: Port to listen on (default ``8080``).
    SHIM_TIMEOUT: Timeout for OPA calls in seconds (default ``1.5``).
"""

from __future__ import annotations

import logging
import os
from typing import Any

from common import UpstreamError, post_json, serve

OPA_URL = os.environ.get("OPA_URL", "http://opa:8181").rstrip("/")
DECISION_PATH = os.environ.get("OPA_DECISION_PATH", "tes/authz/allow").strip("/")
TIMEOUT = float(os.environ.get("SHIM_TIMEOUT", "1.5"))


def decide(req: dict[str, Any], headers: dict[str, str]) -> bool:
    """Ask OPA for the decision on one AuthZEN request.

    Args:
        req: The validated AuthZEN request.
        headers: Headers to forward (``X-Request-ID``).

    Returns:
        The decision; only a boolean ``true`` result allows.

    Raises:
        UpstreamError: If OPA fails or the result is not a boolean.
    """
    answer = post_json(f"{OPA_URL}/v1/data/{DECISION_PATH}", {"input": req}, TIMEOUT, headers)
    result = answer.get("result") if isinstance(answer, dict) else None
    if not isinstance(result, bool):
        raise UpstreamError("OPA result is undefined or not a boolean")
    return result


def main() -> None:
    """Run the front."""
    logging.basicConfig(level=os.environ.get("SHIM_LOG_LEVEL", "INFO"))
    serve(
        int(os.environ.get("SHIM_PORT", "8080")),
        decide,
        {
            "policy_decision_point": os.environ.get("SHIM_BASE_URL", "http://localhost:8080"),
            "access_evaluation_endpoint": os.environ.get("SHIM_BASE_URL", "http://localhost:8080")
            + "/access/v1/evaluation",
        },
    )


if __name__ == "__main__":
    main()

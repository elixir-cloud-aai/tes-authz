"""Client for the recording stub's control API."""

from __future__ import annotations

import json
import urllib.request
from typing import Any

ALLOW: dict[str, Any] = {"status": 200, "body": {"decision": True}}
DENY: dict[str, Any] = {"status": 200, "body": {"decision": False}}


def rule(response: dict[str, Any], **match: str) -> dict[str, Any]:
    """Build a script rule.

    Args:
        response: The response specification.
        **match: Match keys (``action``, ``resource_type``, ``resource_id``,
            ``subject_id``).

    Returns:
        The rule.
    """
    return {"match": match, "response": response}


class StubClient:
    """Scripts the stub and reads its recordings."""

    def __init__(self, base_url: str) -> None:
        """Bind to a stub.

        Args:
            base_url: The stub's base URL (without path).
        """
        self.base_url = base_url.rstrip("/")

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self.base_url + path, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    def reset(self) -> None:
        """Clear script and recordings."""
        self._call("POST", "/_control/reset", {})

    def script(self, default: dict[str, Any] | None = None, rules: list[dict[str, Any]] | None = None) -> None:
        """Set the script.

        Args:
            default: Response when no rule matches (default: deny).
            rules: Rules, first match wins.
        """
        self._call("PUT", "/_control/script", {"default": default or DENY, "rules": rules or []})

    def requests(self) -> list[dict[str, Any]]:
        """Return the recorded requests.

        Returns:
            Recordings with ``headers`` and ``body``, oldest first.
        """
        recorded: list[dict[str, Any]] = self._call("GET", "/_control/requests")
        return recorded

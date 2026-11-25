"""Shared ``service_clients`` policy data for the OPA and OpenFGA setup tests."""

from __future__ import annotations

from typing import Any

LISTED_PAIR = {"iss": "https://iss.example.org/", "client_id": "c1"}
"""A well-formed ``service_clients`` entry."""

MALFORMED_SERVICE_CLIENTS: dict[str, Any] = {
    "null": None,
    "object": LISTED_PAIR,
    "string": [LISTED_PAIR, "https://iss.example.org/ c2"],
    "no-client-id": [LISTED_PAIR, {"iss": "https://iss.example.org/"}],
    "extra-key": [{**LISTED_PAIR, "audiences": ["x"]}],
    "empty-id": [LISTED_PAIR, {"iss": "https://iss.example.org/", "client_id": ""}],
    "empty-iss": [LISTED_PAIR, {"iss": "", "client_id": "c2"}],
    "number": [LISTED_PAIR, {"iss": "https://iss.example.org/", "client_id": 7}],
    "null-id": [LISTED_PAIR, {"iss": "https://iss.example.org/", "client_id": None}],
    "iss-not-string": [LISTED_PAIR, {"iss": ["https://iss.example.org/"], "client_id": "c2"}],
    "space": [LISTED_PAIR, {"iss": "https://iss.example.org/", "client_id": "a b"}],
    "newline": [LISTED_PAIR, {"iss": "https://iss.example.org/\n", "client_id": "c2"}],
    "tab": [LISTED_PAIR, {"iss": "https://iss.example.org/", "client_id": "c\t2"}],
    "del": [LISTED_PAIR, {"iss": "https://iss.example.org/", "client_id": "c2\x7f"}],
    "c1-control": [LISTED_PAIR, {"iss": "https://iss.example.org/", "client_id": "c2\x85"}],
    "non-ascii": [LISTED_PAIR, {"iss": "https://iss.example.org/", "client_id": "cl\u00e9"}],
}
"""Malformed ``service_clients`` values: OPA denies everything, the OpenFGA setup job refuses them.

Shared by ``test_opa_policy.py`` and ``test_common.py``, so both validators see the same data.
"""

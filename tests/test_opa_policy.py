"""The OPA policy with unusual policy data: an ``admins`` key, malformed or missing ``service_clients``."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
POLICY = json.loads((ROOT / "config" / "reference-policy.json").read_text())
OPA = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]["opa"]["image"]
"""The OPA image of ``compose.yaml``."""

pytestmark = [
    pytest.mark.services,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available"),
]

OWN_TASK = {
    "subject": {"type": "user", "id": "u1"},
    "action": {"name": "GetTask", "properties": {"view": "MINIMAL"}},
    "resource": {"type": "tes_task", "id": "t1", "properties": {"owner": "u1", "state": "QUEUED", "tags": {}}},
    "context": {"tes": {"profile": "tes-authzen/3", "service_id": "tes-authz-test"}},
}


LISTED_CREATE = {
    "subject": {
        "type": "user",
        "id": "c1",
        "properties": {"iss": "https://iss.example.org/", "sub": "c1", "client_id": "c1", "claims": {}},
    },
    "action": {"name": "CreateTask", "properties": {}},
    "resource": {
        "type": "tes_task_set",
        "id": "own",
        "properties": {"owner": "c1", "task": {"executors": [{"image": "docker.io/library/alpine:3.20"}]}},
    },
    "context": {"tes": {"profile": "tes-authzen/3", "service_id": "tes-authz-test"}},
}
"""CreateTask by service client ``c1`` of ``https://iss.example.org/``."""

LISTED = [{"iss": "https://iss.example.org/", "client_id": "c1"}]


def _allow(data: dict, tmp_path: Path, request: dict = OWN_TASK) -> bool:
    """Evaluate ``data.tes.authz.allow`` for a request with the given policy data.

    Args:
        data: The policy data (``data.tes_authz``).
        tmp_path: A directory for the data and input files.
        request: The AuthZEN request (default ``OWN_TASK``).

    Returns:
        The decision.
    """
    (tmp_path / "data.json").write_text(json.dumps({"tes_authz": data}))
    (tmp_path / "input.json").write_text(json.dumps(request))
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{ROOT / 'engines' / 'opa' / 'policy'}:/policy:ro",
            "-v",
            f"{tmp_path}:/in:ro",
            OPA,
            "eval",
            "--format=raw",
            "--data=/policy",
            "--data=/in/data.json",
            "--input=/in/input.json",
            "data.tes.authz.allow",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return bool(json.loads(result.stdout))


def test_leftover_admins_deny_everything(tmp_path):
    """An ``admins`` key in the data denies even an owner's own task (fail closed)."""
    tmp_path.chmod(0o755)
    assert _allow(POLICY, tmp_path) is True
    assert _allow({**POLICY, "admins": {"values": ["urn:a"], "prefixes": []}}, tmp_path) is False


def test_service_clients_are_optional(tmp_path):
    """Without ``service_clients`` nobody is a listed client, and everything else decides as before."""
    tmp_path.chmod(0o755)
    without = {k: v for k, v in POLICY.items() if k != "service_clients"}
    assert _allow(without, tmp_path) is True
    assert _allow(without, tmp_path, LISTED_CREATE) is False
    assert _allow({**POLICY, "service_clients": LISTED}, tmp_path, LISTED_CREATE) is True


@pytest.mark.parametrize(
    "clients",
    [
        {"iss": "https://iss.example.org/", "client_id": "c1"},
        [*LISTED, "https://iss.example.org/ c2"],
        [*LISTED, {"iss": "https://iss.example.org/"}],
        [{**LISTED[0], "audiences": ["x"]}],
        [*LISTED, {"iss": "https://iss.example.org/", "client_id": ""}],
        [*LISTED, {"iss": "https://iss.example.org/", "client_id": 7}],
        [*LISTED, {"iss": "https://iss.example.org/", "client_id": "a b"}],
        [*LISTED, {"iss": "https://iss.example.org/\n", "client_id": "c2"}],
    ],
    ids=["object", "string", "no-client-id", "extra-key", "empty-id", "number", "space", "newline"],
)
def test_malformed_service_clients_deny_everything(tmp_path, clients):
    """A malformed ``service_clients`` list denies every request, as the OpenFGA setup job refuses it."""
    tmp_path.chmod(0o755)
    data = {**POLICY, "service_clients": clients}
    assert _allow(data, tmp_path) is False
    assert _allow(data, tmp_path, LISTED_CREATE) is False

"""The OPA policy with policy data from before owner only (an ``admins`` key)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
POLICY = json.loads((ROOT / "config" / "reference-policy.json").read_text())
OPA = "openpolicyagent/opa:1.22.4"
"""The OPA image of ``compose.yaml``."""

pytestmark = pytest.mark.services

OWN_TASK = {
    "subject": {"type": "user", "id": "u1"},
    "action": {"name": "GetTask", "properties": {"view": "MINIMAL"}},
    "resource": {"type": "tes_task", "id": "t1", "properties": {"owner": "u1", "state": "QUEUED", "tags": {}}},
    "context": {"tes": {"profile": "tes-authzen/3", "service_id": "tes-authz-test"}},
}


def _allow(data: dict, tmp_path: Path) -> bool:
    """Evaluate ``data.tes.authz.allow`` for ``OWN_TASK`` with the given policy data.

    Args:
        data: The policy data (``data.tes_authz``).
        tmp_path: A directory for the data and input files.

    Returns:
        The decision.
    """
    (tmp_path / "data.json").write_text(json.dumps({"tes_authz": data}))
    (tmp_path / "input.json").write_text(json.dumps(OWN_TASK))
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
    if not shutil.which("docker"):
        pytest.skip("docker not available")
    tmp_path.chmod(0o755)
    assert _allow(POLICY, tmp_path) is True
    assert _allow({**POLICY, "admins": {"values": ["urn:a"], "prefixes": []}}, tmp_path) is False

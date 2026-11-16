"""The OpenFGA model DSL (for reading) and JSON (for loading) agree."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ENGINE = Path(__file__).resolve().parent.parent / "engines" / "openfga"
CLI = "openfga/cli:v0.9.0"

pytestmark = pytest.mark.services


def _norm(model: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"types": {}, "conditions": {}}
    for t in model["type_definitions"]:
        meta = (t.get("metadata") or {}).get("relations") or {}
        out["types"][t["type"]] = {
            "relations": t.get("relations") or {},
            "direct": {
                name: sorted(
                    json.dumps(
                        {k: v for k, v in u.items() if k in ("type", "wildcard", "condition") and v != ""},
                        sort_keys=True,
                    )
                    for u in rel.get("directly_related_user_types", [])
                )
                for name, rel in meta.items()
                if rel.get("directly_related_user_types")
            },
        }
    for name, cond in (model.get("conditions") or {}).items():
        out["conditions"][name] = {
            "expression": cond["expression"].strip(),
            "parameters": {
                p: (v["type_name"], [g["type_name"] for g in v.get("generic_types", [])])
                for p, v in cond["parameters"].items()
            },
        }
    return out


def test_dsl_matches_json():
    """The DSL model, transformed by the fga CLI, equals model.json."""
    if not shutil.which("docker"):
        pytest.skip("docker not available")
    result = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{ENGINE}:/m:ro", CLI, "model", "transform", "--file", "/m/model.fga"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    from_dsl = json.loads(result.stdout)
    from_json = json.loads((ENGINE / "model.json").read_text())
    assert _norm(from_dsl) == _norm(from_json)

"""Checks of the golden files themselves."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import common
from harness.golden import golden_dirs, load_cases

ROOT = Path(__file__).resolve().parent.parent


def test_generated_golden_files_are_up_to_date():
    """The committed golden files equal the generator output."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_golden.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout


def test_every_golden_case_has_an_expectation():
    """Every golden request has a reference-policy expectation."""
    missing = [c.name for c in load_cases() if "reference_policy" not in c.expect]
    assert not missing, f"no reference_policy expectation: {missing} (add them to golden/expectations.json)"


def test_allowed_cases_follow_the_profile():
    """Every request the policy allows is a valid profile request."""
    for case in load_cases():
        if case.expect.get("reference_policy"):
            common.validate_request(case.request)


def test_tes_recordings_are_read_by_default(monkeypatch):
    """The recordings in `golden/<tes>/` are replayed without any setting."""
    monkeypatch.delenv("TES_AUTHZ_GOLDEN_DIRS", raising=False)
    dirs = golden_dirs()
    assert dirs[0] == ROOT / "golden" / "requests"
    assert ROOT / "golden" / "poiesis" in dirs
    assert ROOT / "golden" / "hook" not in dirs
    names = {c.name for c in load_cases()}
    assert "golden/poiesis/create" in names
    assert not any(name.startswith("golden/hook") for name in names)


def test_golden_dirs_setting_adds_directories(monkeypatch, tmp_path):
    """`TES_AUTHZ_GOLDEN_DIRS` adds directories to the repository's own."""
    shutil.copy(ROOT / "golden" / "poiesis" / "get-other.json", tmp_path / "extra.json")
    monkeypatch.setenv("TES_AUTHZ_GOLDEN_DIRS", f"{tmp_path}::{ROOT / 'golden' / 'poiesis'}")
    dirs = golden_dirs()
    assert dirs[-1] == tmp_path
    assert dirs.count(ROOT / "golden" / "poiesis") == 1
    names = {c.name for c in load_cases()}
    assert "golden/poiesis/create" in names
    assert f"{str(tmp_path.resolve()).lstrip('/')}/extra" in names


def test_poiesis_url_stripping_matches_the_shared_cases():
    """Poiesis recorded exactly the shared URL stripping cases (spec §3.3)."""
    recorded = json.loads((ROOT / "golden" / "poiesis" / "url-stripping.json").read_text())
    assert recorded == json.loads((ROOT / "golden" / "url-stripping.json").read_text())

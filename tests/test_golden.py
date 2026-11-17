"""Checks of the golden files themselves."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import common
import harness.golden as golden
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


def test_golden_dirs_setting_accepts_relative_paths(monkeypatch, tmp_path):
    """Relative paths in `TES_AUTHZ_GOLDEN_DIRS` resolve against the current directory."""
    (tmp_path / "sub").mkdir()
    shutil.copy(ROOT / "golden" / "poiesis" / "get-other.json", tmp_path / "sub" / "extra.json")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TES_AUTHZ_GOLDEN_DIRS", "./sub:sub")
    dirs = golden_dirs()
    assert [d for d in dirs if d.resolve() == (tmp_path / "sub").resolve()] == [Path("sub")]
    assert f"{str((tmp_path / 'sub').resolve()).lstrip('/')}/extra" in {c.name for c in load_cases()}


def test_golden_dirs_setting_rejects_missing_directories(monkeypatch, tmp_path):
    """A missing directory in `TES_AUTHZ_GOLDEN_DIRS` fails instead of shrinking the corpus."""
    missing = tmp_path / "missing"
    monkeypatch.setenv("TES_AUTHZ_GOLDEN_DIRS", str(missing))
    with pytest.raises(ValueError, match=f"no directory {re.escape(str(missing))}"):
        golden_dirs()


def test_external_recordings_load_without_golden_dir(monkeypatch, tmp_path):
    """Without a `golden/` directory, the external recordings still load, hidden files skipped."""
    extra = tmp_path / "extra"
    (extra / ".hidden").mkdir(parents=True)
    shutil.copy(ROOT / "golden" / "poiesis" / "get-other.json", extra / "case.json")
    shutil.copy(ROOT / "golden" / "poiesis" / "get-other.json", extra / ".hidden" / "case.json")
    monkeypatch.setattr(golden, "GOLDEN_ROOT", tmp_path / "golden")
    monkeypatch.setattr(golden, "LOCAL_DIR", tmp_path / "golden" / "requests")
    monkeypatch.setenv("TES_AUTHZ_GOLDEN_DIRS", str(extra))
    assert golden_dirs() == [extra]
    label = str(extra.resolve()).lstrip("/")
    assert [c.name for c in load_cases()] == [f"{label}/case"]


@pytest.mark.parametrize("inside", [False, True])
def test_golden_dirs_setting_rejects_overlapping_directories(monkeypatch, tmp_path, inside):
    """A directory containing, or inside, one already read would read cases twice."""
    root = tmp_path / "golden"
    (root / "requests" / "sub").mkdir(parents=True)
    monkeypatch.setattr(golden, "GOLDEN_ROOT", root)
    monkeypatch.setattr(golden, "LOCAL_DIR", root / "requests")
    monkeypatch.setenv("TES_AUTHZ_GOLDEN_DIRS", str(root / "requests" / "sub" if inside else root))
    with pytest.raises(ValueError, match="read already"):
        golden_dirs()


def test_hidden_and_linked_non_recordings_are_skipped(monkeypatch, tmp_path):
    """Hidden directories and links to `hook/` under `golden/` are no recordings."""
    root = tmp_path / "golden"
    for name in ("requests", "hook", "poiesis", ".ipynb_checkpoints"):
        (root / name).mkdir(parents=True)
    os.symlink(root / "hook", root / "linked")
    monkeypatch.setattr(golden, "GOLDEN_ROOT", root)
    monkeypatch.setattr(golden, "LOCAL_DIR", root / "requests")
    monkeypatch.delenv("TES_AUTHZ_GOLDEN_DIRS", raising=False)
    assert golden.golden_dirs() == [root / "requests", root / "poiesis"]


def test_poiesis_url_stripping_matches_the_shared_cases():
    """Poiesis recorded exactly the shared URL stripping cases (spec §3.3)."""
    recorded = json.loads((ROOT / "golden" / "poiesis" / "url-stripping.json").read_text())
    assert recorded == json.loads((ROOT / "golden" / "url-stripping.json").read_text())

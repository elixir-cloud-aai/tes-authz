"""Checks of the golden files themselves."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import common
from harness.golden import load_cases

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

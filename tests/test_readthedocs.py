"""Checks of the Read the Docs configuration (`.readthedocs.yaml`)."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_readthedocs_pins_the_locked_uv() -> None:
    """Read the Docs installs the version of uv that `uv.lock` locks."""
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    locked = next(p["version"] for p in lock["package"] if p["name"] == "uv")
    config = (ROOT / ".readthedocs.yaml").read_text()
    pins = re.findall(r'"uv==([^"]+)"', config)
    assert pins == [locked], "set the uv pin in .readthedocs.yaml to the version in uv.lock"

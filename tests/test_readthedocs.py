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


def test_readthedocs_reshims_after_installing_uv() -> None:
    """Read the Docs makes the `uv` executable findable after installing it.

    Read the Docs provides Python through asdf, which only finds executables
    that have a shim; `pip install` adds none for `uv`, so the next command
    fails with "uv: not found". Running uv as `python -m uv` doesn't help
    either: once the virtual environment exists, `python` is the one of the
    environment, which has no uv.
    """
    config = (ROOT / ".readthedocs.yaml").read_text()
    commands = [line.strip()[2:] for line in config.splitlines() if line.strip().startswith("- ")]
    install = next(i for i, c in enumerate(commands) if '"uv==' in c)
    assert commands[install + 1] == "asdf reshim python", (
        "run `asdf reshim python` right after installing uv in .readthedocs.yaml"
    )

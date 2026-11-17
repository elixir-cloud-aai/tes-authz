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


def _calls_bare_uv(command: str) -> bool:
    """Tell whether a shell command runs `uv` as an executable.

    Args:
        command: One command of `.readthedocs.yaml`.

    Returns:
        True if a word `uv` isn't preceded by `-m`.
    """
    words = command.split()
    return any(word == "uv" and (i == 0 or words[i - 1] != "-m") for i, word in enumerate(words))


def test_readthedocs_runs_uv_as_a_module() -> None:
    """Read the Docs runs uv as `python -m uv`.

    Read the Docs provides Python through asdf, which creates no shim for
    the `uv` executable that `pip install` adds, so a bare `uv` command fails
    with "uv: not found".
    """
    config = (ROOT / ".readthedocs.yaml").read_text()
    commands = [line.strip()[2:] for line in config.splitlines() if line.strip().startswith("- ")]
    bare = [command for command in commands if _calls_bare_uv(command)]
    assert not bare, f"run uv as `python -m uv` in .readthedocs.yaml: {bare}"


def test_calls_bare_uv() -> None:
    """The check tells bare `uv` calls from module calls."""
    assert _calls_bare_uv('uv venv "x"')
    assert _calls_bare_uv("A=1 uv sync")
    assert not _calls_bare_uv('python -m uv venv "x"')
    assert not _calls_bare_uv('python -m pip install "uv==1.0"')

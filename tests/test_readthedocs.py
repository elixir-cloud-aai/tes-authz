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


def _job_commands(config: str) -> dict[str, list[str]]:
    """Group the commands of `build.jobs` in `.readthedocs.yaml` by job.

    Args:
        config: The text of `.readthedocs.yaml`.

    Returns:
        The commands of each job, in order.
    """
    jobs: dict[str, list[str]] = {}
    job = None
    for line in config.splitlines():
        stripped = line.strip()
        if re.fullmatch(r"    \w+:", line):
            job = stripped[:-1]
            jobs[job] = []
        elif job and stripped.startswith("- "):
            jobs[job].append(stripped[2:])
        elif line and not line.startswith(" " * 4) and not stripped.startswith("#"):
            job = None
    return jobs


def test_readthedocs_reshims_after_installing_uv() -> None:
    """Read the Docs installs uv and reshims asdf before creating the environment.

    Read the Docs provides Python through asdf, which only finds executables
    that have a shim; `pip install` adds none for `uv`, so the next command
    fails with "uv: not found". Running uv as `python -m uv` doesn't help
    either: once the virtual environment exists, `python` is the one of the
    environment, which has no uv.
    """
    jobs = _job_commands((ROOT / ".readthedocs.yaml").read_text())
    pre = jobs.get("pre_create_environment", [])
    assert len(pre) == 2 and '"uv==' in pre[0] and pre[1] == "asdf reshim python", (
        "install uv, then run `asdf reshim python`, in pre_create_environment"
    )
    uses_uv = [c for cs in jobs.values() for c in cs if re.search(r"(^|\s)uv\s", c)]
    assert uses_uv, "the build commands run uv"


def test_job_commands() -> None:
    """The job parser groups commands by job and stops at top-level keys."""
    config = "build:\n  jobs:\n    a:\n      - x\n    b:\n      - y\n      - z\nmkdocs:\n  - q\n"
    assert _job_commands(config) == {"a": ["x"], "b": ["y", "z"]}

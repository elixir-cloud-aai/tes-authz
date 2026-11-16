"""Per-worktree stack settings (``harness/stack.py``) against compose."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from harness import stack

COMPOSE = Path(__file__).resolve().parent.parent / "compose.yaml"


@pytest.fixture
def clean_env(monkeypatch):
    """No stack variables from the caller's environment."""
    for name in ("TES_AUTHZ_PROJECT", "TES_AUTHZ_PORT_BASE", *(f"TES_AUTHZ_{n}_PORT" for n in stack.PORT_OFFSETS)):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_defaults_are_the_original_ports(clean_env):
    """Without settings, the main checkout keeps its project and ports."""
    assert stack.project() == "tes-authz"
    assert {n: stack.port(n) for n in stack.PORT_OFFSETS} == {
        "OPENFGA": 18080,
        "OPA": 18181,
        "OPA_FRONT": 18190,
        "OPENFGA_SHIM": 18191,
        "STUB": 18192,
        "OIDC": 18193,
    }


def test_port_base_and_override(clean_env):
    """The base shifts every port; a single-port variable still wins."""
    clean_env.setenv("TES_AUTHZ_PORT_BASE", "18300")
    clean_env.setenv("TES_AUTHZ_STUB_PORT", "19999")
    assert stack.port("OPENFGA") == 18300 and stack.port("OIDC") == 18413
    assert stack.port("STUB") == 19999
    assert max(stack.PORT_OFFSETS.values()) < stack.BLOCK_SIZE


@pytest.mark.parametrize("name", ["", "Tes", "a b", "x;rm", "-x"])
def test_project_name_checked(clean_env, name):
    """Only compose project names are accepted (they go into shell exports)."""
    clean_env.setenv("TES_AUTHZ_PROJECT", name)
    with pytest.raises(ValueError, match="TES_AUTHZ_PROJECT"):
        stack.project()


def test_exports_run_as_script(clean_env):
    """``python3 harness/stack.py`` prints the exports compose needs."""
    clean_env.setenv("TES_AUTHZ_PROJECT", "tes-authz-tesp")
    clean_env.setenv("TES_AUTHZ_PORT_BASE", "18700")
    script = Path(stack.__file__)
    out = subprocess.run([sys.executable, "-I", str(script)], capture_output=True, text=True, check=True).stdout
    assert "export TES_AUTHZ_PROJECT=tes-authz-tesp" in out
    assert "export TES_AUTHZ_OIDC_PORT=18813" in out


def test_compose_uses_every_port_and_the_project():
    """Every published port in compose is one of the stack's variables, and names follow the project."""
    text = COMPOSE.read_text()
    published = set(re.findall(r'"127\.0\.0\.1:\$\{TES_AUTHZ_(\w+)_PORT:-(\d+)\}:', text))
    assert {name for name, _ in published} == set(stack.PORT_OFFSETS)
    assert all(int(default) == stack.DEFAULT_PORT_BASE + stack.PORT_OFFSETS[name] for name, default in published)
    assert "name: ${TES_AUTHZ_PROJECT:-tes-authz}" in text
    names = re.findall(r"container_name: (\S+)", text)
    assert names and all(n.startswith("${TES_AUTHZ_PROJECT:-tes-authz}-") for n in names)

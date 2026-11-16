"""Per-worktree stack settings: compose project name and host port block.

Several worktrees (one per TES) can run their own stack side by side when
each sets its own project and port block:

* ``TES_AUTHZ_PROJECT`` (default ``tes-authz``): compose project name and
  container name prefix (``<project>-opa``, ``<project>-oidc``, ...); the
  compose network is ``<project>_default``.
* ``TES_AUTHZ_PORT_BASE`` (default 18080): first port of the block. Ports
  are ``base + offset`` with the offsets below; the defaults reproduce the
  original ports 18080, 18181 and 18190-18193.
* ``TES_AUTHZ_<NAME>_PORT`` still overrides a single port.

``scripts/test.sh`` and the Makefile export these values to compose with
``eval "$(python -m harness.stack)"``; the harness reads them through this
module, so compose and tests always agree.
"""

from __future__ import annotations

import os
import re
import shlex

DEFAULT_PROJECT = "tes-authz"
"""Project name of the main checkout."""

DEFAULT_PORT_BASE = 18080
"""Port block of the main checkout."""

PORT_OFFSETS: dict[str, int] = {
    "OPENFGA": 0,
    "OPA": 101,
    "OPA_FRONT": 110,
    "OPENFGA_SHIM": 111,
    "STUB": 112,
    "OIDC": 113,
}
"""Offset of each published service port from the port base."""

BLOCK_SIZE = 200
"""Ports reserved per block; port bases should be this far apart."""


def project() -> str:
    """Return the compose project name.

    Returns:
        ``TES_AUTHZ_PROJECT`` or the default.

    Raises:
        ValueError: If the name is not a valid compose project name.
    """
    name = os.environ.get("TES_AUTHZ_PROJECT", DEFAULT_PROJECT)
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name):
        raise ValueError(f"TES_AUTHZ_PROJECT must be a compose project name, got {name!r}")
    return name


def port_base() -> int:
    """Return the first port of the block.

    Returns:
        ``TES_AUTHZ_PORT_BASE`` or the default.
    """
    return int(os.environ.get("TES_AUTHZ_PORT_BASE", str(DEFAULT_PORT_BASE)))


def port(name: str) -> int:
    """Return the host port of a service.

    Args:
        name: Key of ``PORT_OFFSETS`` (e.g. ``OIDC``).

    Returns:
        ``TES_AUTHZ_<name>_PORT`` if set, else base + offset.
    """
    override = os.environ.get(f"TES_AUTHZ_{name}_PORT")
    return int(override) if override else port_base() + PORT_OFFSETS[name]


def exports() -> str:
    """Return shell ``export`` lines for compose.

    Returns:
        One ``export`` line per variable.
    """
    values = {"TES_AUTHZ_PROJECT": project(), **{f"TES_AUTHZ_{n}_PORT": str(port(n)) for n in PORT_OFFSETS}}
    return "\n".join(f"export {key}={shlex.quote(value)}" for key, value in values.items())


if __name__ == "__main__":
    print(exports())

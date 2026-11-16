"""Registry of decision services (engines) under test.

Adding an engine means: a compose service (plus a shim if the engine needs
one) and one ``Engine`` entry here. The replay tests and the smoke tests
pick every entry up without further changes.
"""

from __future__ import annotations

from dataclasses import dataclass

from harness.stack import port


@dataclass(frozen=True)
class Engine:
    """A decision service reachable over AuthZEN (or a native API).

    Attributes:
        name: Short name used in test IDs.
        host_url: Evaluation URL as seen from the host (tests, host TESes).
        network_url: Evaluation URL as seen from containers on the compose
            network (containerised TESes in phase 2).
        policy: Name of the expectation set in the golden files.
        authzen: Whether the URL speaks AuthZEN; otherwise it is the OPA
            Data API, used to check the policy without the front.
    """

    name: str
    host_url: str
    network_url: str
    policy: str = "reference_policy"
    authzen: bool = True


OPA_PORT = port("OPA")
OPA_FRONT_PORT = port("OPA_FRONT")
OPENFGA_PORT = port("OPENFGA")
OPENFGA_SHIM_PORT = port("OPENFGA_SHIM")
STUB_PORT = port("STUB")

ENGINES: dict[str, Engine] = {
    "opa": Engine(
        "opa",
        f"http://127.0.0.1:{OPA_FRONT_PORT}/access/v1/evaluation",
        "http://opa-front:8080/access/v1/evaluation",
    ),
    "openfga": Engine(
        "openfga",
        f"http://127.0.0.1:{OPENFGA_SHIM_PORT}/access/v1/evaluation",
        "http://openfga-shim:8080/access/v1/evaluation",
    ),
}
"""Engines that answer the AuthZEN profile (through their shim if needed)."""

OPA_DATA_API = Engine(
    "opa-data-api",
    f"http://127.0.0.1:{OPA_PORT}/v1/data/tes/authz/allow",
    "http://opa:8181/v1/data/tes/authz/allow",
    authzen=False,
)
"""OPA without the front: proves the Rego policy enforces the contract itself."""

STUB = Engine(
    "stub",
    f"http://127.0.0.1:{STUB_PORT}/access/v1/evaluation",
    "http://stub:8080/access/v1/evaluation",
    policy="scripted",
)
"""The recording stub for hook conformance (layer 1)."""

OPENFGA_API = f"http://127.0.0.1:{OPENFGA_PORT}"
"""OpenFGA's native HTTP API on the host (findings tests only)."""

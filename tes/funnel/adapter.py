"""Adapter for Funnel (calypr/funnel, test fork ``uniqueg/funnel`` branch ``feat/authzen-hook``).

Funnel runs on the host as one ``funnel server run`` process from the binary
``TES_AUTHZ_FUNNEL_BIN`` (default: ``.tools/funnel`` in the clone
``~/Work/agent-clones/tes-authz-funnel``; build it there with
``.tools/run go build -o .tools/funnel .``). Each ``start`` writes a fresh
configuration and an empty embedded database (BoltDB) under
``.cache/funnel/`` and restarts the process.

Compute: ``noop`` by default, so tasks stay ``QUEUED`` (the suites check that
denied or failed calls leave tasks unchanged). ``TES_AUTHZ_FUNNEL_COMPUTE=local``
runs tasks with the local backend (Docker); its workers read tasks over the
TES API with the Basic admin credentials ``worker``, which the hook leaves
to ``TaskAccess``.

OIDC: the harness's mock issuer ``a`` (host URL), audience
``harness.oidc.AUDIENCE``. ``auth.oidc.timeout`` (``Server.OidcAuth.Timeout``)
and the decision-service timeout follow ``HookConfig.timeout``.

Funnel's service-info id is fixed (``org.ga4gh.funnel``), so
``subject_fixtures`` returns it as ``service_id`` for the golden request.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from harness.engines import ENGINES, STUB
from harness.oidc import AUDIENCE, OIDC, default_claims, issuer_url
from harness.tes import HookConfig, Identity

CLONE = Path(os.environ.get("TES_AUTHZ_FUNNEL_DIR", Path.home() / "Work/agent-clones/tes-authz-funnel"))
BINARY = os.environ.get("TES_AUTHZ_FUNNEL_BIN", str(CLONE / ".tools/funnel"))
HTTP_PORT = int(os.environ.get("TES_AUTHZ_FUNNEL_HTTP_PORT", "18460"))
RPC_PORT = int(os.environ.get("TES_AUTHZ_FUNNEL_RPC_PORT", "18461"))
COMPUTE = os.environ.get("TES_AUTHZ_FUNNEL_COMPUTE", "noop")
STATE = Path(__file__).resolve().parents[2] / ".cache" / "funnel"
ISSUER = issuer_url("a")
SERVICE_ID = "org.ga4gh.funnel"
WORKER = {"User": "worker", "Password": "tes-authz-funnel-worker", "Admin": True}


def _wait(url: str, process: subprocess.Popen[bytes], seconds: float = 30) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Funnel exited with {process.returncode}; see {STATE / 'funnel.log'}")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            time.sleep(0.2)
    raise RuntimeError(f"Funnel did not come up at {url}")


def configuration(config: HookConfig) -> dict[str, Any]:
    """Map a hook configuration onto Funnel's configuration file.

    Args:
        config: The AuthZ configuration.

    Returns:
        Funnel's configuration (YAML accepts it as JSON).
    """
    timeout = f"{config.timeout}s"
    authz: dict[str, Any] = {}
    if config.decision_service is not None:
        engine = STUB if config.decision_service == "stub" else ENGINES[config.decision_service]
        authz["DecisionService"] = {"URL": engine.host_url, "Timeout": timeout, "Claims": list(config.claims)}
    if config.required_claim is not None:
        rule = config.required_claim
        authz["RequiredClaim"] = {"Name": rule.name, "Values": list(rule.values), "Prefixes": list(rule.prefixes)}
    return {
        "Database": "boltdb",
        "Compute": COMPUTE,
        "EventWriters": ["boltdb"],
        "Logger": {"Level": "info", "OutputFile": str(STATE / "funnel.log")},
        "BoltDB": {"Path": str(STATE / "funnel.db")},
        "Worker": {"WorkDir": str(STATE / "work")},
        "LocalStorage": {"AllowedDirs": [str(STATE / "work")]},
        "RPCClient": {"ServerAddress": f"127.0.0.1:{RPC_PORT}", "Credential": WORKER},
        "Server": {
            "HostName": "127.0.0.1",
            "HTTPPort": str(HTTP_PORT),
            "RPCPort": str(RPC_PORT),
            "BasicAuth": [WORKER],
            "OidcAuth": {
                "ServiceConfigURL": ISSUER + "/.well-known/openid-configuration",
                "ClientId": "funnel",
                "ClientSecret": "tes-authz-funnel-unused",
                "RequireAudience": AUDIENCE,
                "RedirectURL": f"http://127.0.0.1:{HTTP_PORT}/login",
                "Timeout": timeout,
                "Userinfo": {"Enabled": config.userinfo},
            },
            "Authz": authz,
        },
    }


class Funnel:
    """Runs Funnel with the hook configuration of each test."""

    name = "funnel"
    features = frozenset({"keyset-cursor", "userinfo", "userinfo-cache", "userinfo-timeout"})

    def __init__(self) -> None:
        """Start nothing yet."""
        self._process: subprocess.Popen[bytes] | None = None

    def start(self, config: HookConfig) -> str:
        """Restart Funnel with an empty database and this configuration.

        Args:
            config: The AuthZ configuration.

        Returns:
            The base URL.
        """
        self.stop()
        shutil.rmtree(STATE, ignore_errors=True)
        STATE.mkdir(parents=True)
        path = STATE / "funnel.config.yml"
        path.write_text(json.dumps(configuration(config)))
        path.chmod(0o600)
        command = [BINARY, "server", "run", "--config", str(path)]
        self._process = subprocess.Popen(command, cwd=STATE)  # noqa: S603
        base = f"http://127.0.0.1:{HTTP_PORT}/ga4gh/tes/v1"
        _wait(base + "/service-info", self._process)
        return base

    def stop(self) -> None:
        """Stop Funnel if it runs."""
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
            self._process = None

    def token(self, identity: Identity) -> str:
        """Return a JWT from the mock issuer.

        Args:
            identity: The identity.

        Returns:
            The bearer token.
        """
        return OIDC.token_for(identity)

    def owner_id(self, identity: Identity) -> str:
        """Return ``sub``: Funnel stamps the token subject as owner.

        Args:
            identity: The identity.

        Returns:
            The owner ID.
        """
        return identity.sub

    def subject_fixtures(self, identity: Identity) -> dict[str, Any]:
        """Return the issuer, client ID and Funnel's fixed service ID.

        Args:
            identity: The identity.

        Returns:
            Placeholder name to value.
        """
        claims = default_claims(identity)
        return {"iss": ISSUER, "client_id": claims.get("azp", claims.get("client_id")), "service_id": SERVICE_ID}


ADAPTER = Funnel()

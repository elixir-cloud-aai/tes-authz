"""Adapter for TESP (CESNET/tesp-api, test fork ``uniqueg/tesp-api`` branch ``feat/authzen-hook``).

TESP runs on the host as a uvicorn process from its clone and virtual
environment (``TES_AUTHZ_TESP_DIR``, default ``~/Work/agent-clones/tes-authz-tesp``),
against MongoDB in the container ``tes-authz-tesp-mongo`` (``tes/tesp/up.sh``).
Each ``start`` drops TESP's database and restarts the process with the
configuration mapped onto TESP's Dynaconf environment variables
(``TESP_API_AUTHZ__...``).

Pulsar: by default, TESP's Pulsar URL points at a local socket that accepts
connections and never answers, so tasks stay ``QUEUED`` (the suites check that
denied or failed calls leave tasks unchanged). Set ``TES_AUTHZ_TESP_PULSAR`` to
a real Pulsar URL (``tes/tesp/up.sh --pulsar`` starts ``tes-authz-tesp-pulsar``)
to run against Pulsar; tasks then move on.

OIDC: ``tes/tesp/issuer.py`` runs with TESP's interpreter and mints RS256 tokens.
TODO(phase2/oidc): use the shared mock issuer once that branch is merged.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess  # noqa: S404 - starts the TES under test
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from harness.engines import ENGINES, STUB
from harness.tes import HookConfig, Identity

HERE = Path(__file__).resolve().parent
TESP_DIR = Path(os.environ.get("TES_AUTHZ_TESP_DIR", Path.home() / "Work/agent-clones/tes-authz-tesp"))
PYTHON = str(TESP_DIR / ".venv/bin/python")
PORT = int(os.environ.get("TES_AUTHZ_TESP_PORT", "18300"))
ISSUER_PORT = int(os.environ.get("TES_AUTHZ_TESP_ISSUER_PORT", "18301"))
HOLD_PORT = int(os.environ.get("TES_AUTHZ_TESP_HOLD_PORT", "18302"))
MONGO_URI = os.environ.get("TES_AUTHZ_TESP_MONGO_URI", "mongodb://127.0.0.1:18303")
PULSAR_URL = os.environ.get("TES_AUTHZ_TESP_PULSAR", f"http://127.0.0.1:{HOLD_PORT}")
ISSUER = f"http://127.0.0.1:{ISSUER_PORT}"
AUDIENCE = "tesp-api"


def _wait(url: str, what: str, process: subprocess.Popen[bytes] | None = None, seconds: float = 30) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"{what} exited with {process.returncode}")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            time.sleep(0.2)
    raise RuntimeError(f"{what} did not come up at {url}")


class _Hold:
    """A socket that accepts connections and never answers (a stalled Pulsar)."""

    def __init__(self, port: int) -> None:
        self._server = socket.create_server(("127.0.0.1", port))
        self._held: list[socket.socket] = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                connection, _ = self._server.accept()
            except OSError:
                return
            self._held.append(connection)


class Tesp:
    """Runs TESP from its clone with the hook configuration of each test."""

    name = "tesp"
    features = frozenset({"keyset-cursor"})

    def __init__(self) -> None:
        """Start nothing yet."""
        self._process: subprocess.Popen[bytes] | None = None
        self._issuer: subprocess.Popen[bytes] | None = None
        self._hold: _Hold | None = None

    def _environment(self, config: HookConfig) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith("TESP_API_")}
        env.update(
            {
                "TESP_API_DB__MONGODB_URI": MONGO_URI,
                "TESP_API_PULSAR__URL": PULSAR_URL,
                "TESP_API_PULSAR__CLIENT_TIMEOUT": "3600",
                "TESP_API_LOGGING__LEVEL": "INFO",
                "TESP_API_OAUTH__ENABLE": "true",
                "TESP_API_OAUTH__ISSUERS": json.dumps([ISSUER]),
                "TESP_API_OAUTH__AUDIENCE": AUDIENCE,
                "TESP_API_SERVICE_INFO__ID": config.service_id,
            }
        )
        if config.decision_service is not None:
            engine = STUB if config.decision_service == "stub" else ENGINES[config.decision_service]
            env["TESP_API_AUTHZ__DECISION_SERVICE__URL"] = engine.host_url
            env["TESP_API_AUTHZ__DECISION_SERVICE__TIMEOUT"] = str(config.timeout)
            if config.claims:
                env["TESP_API_AUTHZ__DECISION_SERVICE__CLAIMS"] = json.dumps(list(config.claims))
        rule = config.required_claim
        if rule is not None:
            env["TESP_API_AUTHZ__REQUIRED_CLAIM__NAME"] = rule.name
            if rule.values:
                env["TESP_API_AUTHZ__REQUIRED_CLAIM__VALUES"] = json.dumps(list(rule.values))
            if rule.prefixes:
                env["TESP_API_AUTHZ__REQUIRED_CLAIM__PREFIXES"] = json.dumps(list(rule.prefixes))
        return env

    def start(self, config: HookConfig) -> str:
        """Restart TESP with an empty database and this configuration.

        Args:
            config: The AuthZ configuration.

        Returns:
            The base URL.
        """
        if config.userinfo:
            raise NotImplementedError("TESP has no userinfo lookup")
        self.stop()
        if self._issuer is None or self._issuer.poll() is not None:
            self._issuer = subprocess.Popen([PYTHON, str(HERE / "issuer.py"), str(ISSUER_PORT)])  # noqa: S603
            _wait(ISSUER + "/jwks", "issuer", self._issuer)
        if self._hold is None and "TES_AUTHZ_TESP_PULSAR" not in os.environ:
            self._hold = _Hold(HOLD_PORT)
        drop = f"import pymongo; pymongo.MongoClient({MONGO_URI!r}).drop_database('tesp')"
        subprocess.run([PYTHON, "-c", drop], check=True, timeout=30)  # noqa: S603
        command = [PYTHON, "-m", "uvicorn", "tesp_api.tesp_api:app", "--host", "127.0.0.1", "--port", str(PORT)]
        self._process = subprocess.Popen(command, cwd=TESP_DIR, env=self._environment(config))  # noqa: S603
        base = f"http://127.0.0.1:{PORT}/v1"
        _wait(base + "/service-info", "TESP", self._process)
        return base

    def stop(self) -> None:
        """Stop TESP (the issuer and the Pulsar hold stay for the next start)."""
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
            self._process = None

    def token(self, identity: Identity) -> str:
        """Mint an RS256 token at the adapter's issuer.

        Args:
            identity: The identity.

        Returns:
            The bearer token.
        """
        now = int(time.time())
        claims: dict[str, Any] = {"iss": ISSUER, "sub": identity.sub, "aud": AUDIENCE, "iat": now, "exp": now + 600}
        claims.update(identity.claims)
        if identity.client_credentials:
            claims.setdefault("client_id", identity.sub)
        else:
            claims.setdefault("azp", "tes-client")
        request = urllib.request.Request(ISSUER + "/_mint", data=json.dumps(claims).encode(), method="POST")
        request.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(request, timeout=10) as response:
            token: str = json.loads(response.read())["token"]
        return token

    def owner_id(self, identity: Identity) -> str:
        """Return ``sub`` (one configured issuer).

        Args:
            identity: The identity.

        Returns:
            The owner ID.
        """
        return identity.sub

    def subject_fixtures(self, identity: Identity) -> dict[str, Any]:
        """Return the issuer and client ID the tokens carry.

        Args:
            identity: The identity.

        Returns:
            Placeholder name to value.
        """
        client = identity.sub if identity.client_credentials else "tes-client"
        return {"iss": ISSUER, "client_id": identity.claims.get("client_id", identity.claims.get("azp", client))}


ADAPTER = Tesp()

"""Adapter for TESK (elixir-cloud-aai/tesk-api, branch ``feat/199-authzen-decision-service``).

TESK API runs as the jar of its clone (``TES_AUTHZ_TESK_DIR``, default
``~/Work/agent-clones/tes-authz-tesk``; build it with ``mvn package``) in the
container ``tes-authz-tesk-api`` (``eclipse-temurin:21-jre``) on the host
network, so it reaches the engines, the stub and the mock issuer on loopback.
Its Kubernetes is the kind cluster ``tes-authz-tesk`` (``tes/tesk/up.sh``),
through the kubeconfig ``<clone>/.cache/kind-kubeconfig``. TESK API only
creates taskmaster jobs there; whether they run doesn't matter to the suites
(the namespace has no taskmaster service account, so tasks stay ``QUEUED`` or
fail; denied calls must leave them unchanged either way). Each ``start``
deletes the jobs of earlier runs and restarts the container with the
configuration mapped onto TESK's environment variables
(``TESK_API_AUTHZ_*``, ``TESK_API_AUTH_OIDC_TIMEOUT``).

OIDC: TESK validates opaque tokens at the user info endpoint only, so user
tokens are minted with ``fmt="opaque"`` at the mock issuer ``a`` (host URL).
TESK can't tell the issuer from the user info, so ``tesk.api.authz.issuer`` is
set to it, and owners are ``<iss>|<sub>``. Client-credentials identities get
JWTs, which TESK checks locally as tokens of listed service clients
(``TESK_API_AUTHORISATION_SERVICE_CLIENTS_*``, client IDs from
``SERVICE_CLIENTS``); their subject then has ``client_id`` and ``scope``.

Without a decision service, the built-in model is TESK's claim authorisation
on ``azp`` (``harness.oidc.CLIENT_ID``): users own their tasks, without groups.
TESK has no switch for user info (always on), so ``HookConfig.userinfo`` is
ignored.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from harness.engines import ENGINES, STUB
from harness.oidc import CLIENT_ID, OIDC, issuer_url
from harness.tes import HookConfig, Identity

TESK_DIR = Path(os.environ.get("TES_AUTHZ_TESK_DIR", Path.home() / "Work/agent-clones/tes-authz-tesk"))
KUBECONFIG = Path(os.environ.get("TES_AUTHZ_TESK_KUBECONFIG", TESK_DIR / ".cache/kind-kubeconfig"))
PORT = int(os.environ.get("TES_AUTHZ_TESK_PORT", "18450"))
CONTAINER = "tes-authz-tesk-api"
IMAGE = os.environ.get("TES_AUTHZ_TESK_IMAGE", "eclipse-temurin:21-jre")
NAMESPACE = "default"
ISSUER = issuer_url("a")
SERVICE_CLIENTS = ("protes",)
BASE_PATH = "/ga4gh/tes/v1"


def _jar() -> Path:
    jars = sorted(p for p in (TESK_DIR / "target").glob("tesk-*.jar") if not p.name.endswith("-plain.jar"))
    if not jars:
        raise RuntimeError(f"no TESK jar in {TESK_DIR / 'target'}; run mvn package there")
    return jars[-1]


def _wait(url: str, seconds: float = 90) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        state = subprocess.run(  # noqa: S603
            ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        if state != "true":
            logs = subprocess.run(["docker", "logs", "--tail", "40", CONTAINER], capture_output=True, text=True, check=False)  # noqa: S603, S607
            raise RuntimeError(f"TESK exited:\n{logs.stdout}{logs.stderr}")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:  # noqa: S310
                if response.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    raise RuntimeError(f"TESK did not come up at {url}")


class Tesk:
    """Runs TESK API in a container with the hook configuration of each test."""

    name = "tesk"
    features = frozenset({"userinfo", "userinfo-timeout", "opaque-tokens", "scope-bound-cursor"})

    def _environment(self, config: HookConfig) -> dict[str, str]:
        env = {
            "SPRING_PROFILES_ACTIVE": "auth",
            "SECURITY_OAUTH2_RESOURCE_USER_INFO_URI": ISSUER + "/userinfo",
            "SERVER_PORT": str(PORT),
            "TESK_API_K8S_NAMESPACE": NAMESPACE,
            "TESK_API_SERVICE_INFO_LOCATION": "file:/tesk/service-info.yaml",
            "TESK_API_AUTH_OIDC_TIMEOUT": str(config.timeout),
            "TESK_API_AUTHZ_ISSUER": ISSUER,
            # built-in model: users with the harness client's azp, without groups
            "TESK_API_AUTHORISATION_CLAIM_ENABLED": "true",
            "TESK_API_AUTHORISATION_CLAIM_NAME": "azp",
            "TESK_API_AUTHORISATION_CLAIM_VALUES": CLIENT_ID,
            "TESK_API_AUTHORISATION_SERVICE_CLIENTS_ENABLED": "true",
            "TESK_API_AUTHORISATION_SERVICE_CLIENTS_ISSUER": ISSUER,
            "TESK_API_AUTHORISATION_SERVICE_CLIENTS_CLIENT_IDS": ",".join(SERVICE_CLIENTS),
            "TESK_API_AUTHORISATION_SERVICE_CLIENTS_REQUIRE_ACCESS_TOKEN_TYPE": "false",
        }
        if config.decision_service is not None:
            engine = STUB if config.decision_service == "stub" else ENGINES[config.decision_service]
            env["TESK_API_AUTHZ_DECISION_SERVICE_URL"] = engine.host_url
            env["TESK_API_AUTHZ_DECISION_SERVICE_TIMEOUT"] = str(config.timeout)
            if config.claims:
                env["TESK_API_AUTHZ_DECISION_SERVICE_CLAIMS"] = json.dumps(list(config.claims))
        rule = config.required_claim
        if rule is not None:
            env["TESK_API_AUTHZ_REQUIRED_CLAIM_NAME"] = rule.name
            if rule.values:
                env["TESK_API_AUTHZ_REQUIRED_CLAIM_VALUES"] = json.dumps(list(rule.values))
            if rule.prefixes:
                env["TESK_API_AUTHZ_REQUIRED_CLAIM_PREFIXES"] = json.dumps(list(rule.prefixes))
        return env

    def start(self, config: HookConfig) -> str:
        """Restart TESK with no tasks and this configuration.

        Args:
            config: The AuthZ configuration.

        Returns:
            The base URL.
        """
        self.stop()
        subprocess.run(  # noqa: S603
            ["kubectl", "--kubeconfig", str(KUBECONFIG), "-n", NAMESPACE, "delete", "jobs,configmaps", "--all", "--wait=false"],  # noqa: S607
            check=True,
            capture_output=True,
            timeout=60,
        )
        state = TESK_DIR / ".cache/harness"
        state.mkdir(parents=True, exist_ok=True)
        template = (TESK_DIR / "src/main/resources/service-info.yaml").read_text().splitlines()
        lines = [f"id: '{config.service_id}'" if line.startswith("id:") else line for line in template]
        (state / "service-info.yaml").write_text("\n".join(lines) + "\n")
        command = ["docker", "run", "-d", "--name", CONTAINER, "--network", "host", "--user", f"{os.getuid()}:{os.getgid()}"]
        for key, value in self._environment(config).items():
            command += ["-e", f"{key}={value}"]
        command += [
            "-e", "KUBECONFIG=/tesk/kubeconfig",
            "-v", f"{_jar()}:/tesk/tesk.jar:ro",
            "-v", f"{KUBECONFIG}:/tesk/kubeconfig:ro",
            "-v", f"{state / 'service-info.yaml'}:/tesk/service-info.yaml:ro",
            IMAGE, "java", "-jar", "/tesk/tesk.jar",
        ]  # fmt: skip
        subprocess.run(command, check=True, capture_output=True, timeout=120)  # noqa: S603
        base = f"http://127.0.0.1:{PORT}{BASE_PATH}"
        _wait(base + "/service-info")
        return base

    def stop(self) -> None:
        """Remove the TESK container."""
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True, check=False)  # noqa: S603, S607

    def token(self, identity: Identity) -> str:
        """Mint an opaque token (users) or a JWT (listed service clients) at the mock issuer.

        Args:
            identity: The identity.

        Returns:
            The bearer token.
        """
        if identity.client_credentials and identity.sub in SERVICE_CLIENTS:
            return OIDC.token_for(identity)
        return OIDC.token_for(identity, fmt="opaque")

    def owner_id(self, identity: Identity) -> str:
        """Return ``<iss>|<sub>`` (the client ID for service clients, which is their ``sub``).

        Args:
            identity: The identity.

        Returns:
            The owner ID.
        """
        return f"{ISSUER}|{identity.sub}"

    def subject_fixtures(self, identity: Identity) -> dict[str, Any]:
        """Return the issuer, and the client ID that TESK sends only for service clients.

        Args:
            identity: The identity.

        Returns:
            Placeholder name to value.
        """
        client_id = identity.sub if identity.client_credentials and identity.sub in SERVICE_CLIENTS else None
        return {"iss": ISSUER, "client_id": client_id}


ADAPTER = Tesk()

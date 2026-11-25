"""The OPA decision service of the container image: OPA and its front in one.

The image (``Dockerfile``) runs this module as its entry point. It starts
OPA with the policy baked into the image and the operator's policy data,
bound to loopback, so that OPA's unauthenticated Data API is never reachable
from outside the container; waits until OPA is healthy; then serves the
AuthZEN front (``opa_front.decide`` behind ``common.make_handler``) on
``TES_AUTHZ_HOST``:``TES_AUTHZ_PORT``. If OPA exits, the front stops and the
process exits with status 1, so that the container restarts instead of
answering ``502`` for good. ``SIGTERM`` and ``SIGINT`` stop both, with
status 0.

Settings (environment):
    TES_AUTHZ_DATA: Policy data file, a JSON object (default
        ``/etc/tes-authz/data.json``); loaded as ``data.tes_authz``.
    TES_AUTHZ_POLICY: Directory of the Rego policy (default
        ``/opt/tes-authz/policy``, the policy of the image).
    TES_AUTHZ_HOST: Address of the front (default ``0.0.0.0``; ``127.0.0.1``
        for a sidecar that only its pod may reach).
    TES_AUTHZ_PORT: Port of the front (default ``8080``).
    TES_AUTHZ_OPA_PORT: Loopback port of OPA (default ``8181``).
    TES_AUTHZ_OPA: OPA executable (default ``opa``, on ``PATH``).
    TES_AUTHZ_STARTUP_TIMEOUT: Seconds to wait for OPA (default ``30``).
    SHIM_BASE_URL: Base URL served in ``/.well-known/authzen-configuration``
        (default ``http://localhost:<port>``).
    SHIM_TIMEOUT, SHIM_LOG_LEVEL, SHIM_MAX_BODY_BYTES: As for the front.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import FrameType
from typing import Any

import opa_front
from common import make_handler

log = logging.getLogger("tes-authz-service")


class ConfigError(ValueError):
    """Raised when the settings or the policy data are unusable."""


@dataclass(frozen=True)
class Settings:
    """Settings of the service, from the environment.

    Attributes:
        data: Policy data file.
        policy: Directory of the Rego policy.
        host: Address of the front.
        port: Port of the front.
        opa_port: Loopback port of OPA.
        opa: OPA executable.
        startup_timeout: Seconds to wait for OPA.
        base_url: Base URL for the AuthZEN metadata.
    """

    data: Path
    policy: Path
    host: str
    port: int
    opa_port: int
    opa: str
    startup_timeout: float
    base_url: str

    @property
    def opa_url(self) -> str:
        """Base URL of OPA on loopback."""
        return f"http://127.0.0.1:{self.opa_port}"


def _port(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name, str(default))
    try:
        port = int(raw)
    except ValueError:
        raise ConfigError(f"{name} is not a port: {raw!r}") from None
    if not 0 < port < 65536:
        raise ConfigError(f"{name} is not a port: {raw!r}")
    return port


def load_settings(env: Mapping[str, str]) -> Settings:
    """Read the settings from the environment.

    Args:
        env: The environment.

    Returns:
        The settings.

    Raises:
        ConfigError: If a setting is invalid.
    """
    port = _port(env, "TES_AUTHZ_PORT", 8080)
    opa_port = _port(env, "TES_AUTHZ_OPA_PORT", 8181)
    if opa_port == port:
        raise ConfigError("TES_AUTHZ_OPA_PORT must differ from TES_AUTHZ_PORT")
    raw_timeout = env.get("TES_AUTHZ_STARTUP_TIMEOUT", "30")
    try:
        startup_timeout = float(raw_timeout)
    except ValueError:
        raise ConfigError(f"TES_AUTHZ_STARTUP_TIMEOUT is not a number: {raw_timeout!r}") from None
    if not startup_timeout > 0:
        raise ConfigError(f"TES_AUTHZ_STARTUP_TIMEOUT must be positive: {raw_timeout!r}")
    host = env.get("TES_AUTHZ_HOST", "0.0.0.0")  # noqa: S104 (inside a container)
    if not host:
        raise ConfigError("TES_AUTHZ_HOST is empty")
    return Settings(
        data=Path(env.get("TES_AUTHZ_DATA", "/etc/tes-authz/data.json")),
        policy=Path(env.get("TES_AUTHZ_POLICY", "/opt/tes-authz/policy")),
        host=host,
        port=port,
        opa_port=opa_port,
        opa=env.get("TES_AUTHZ_OPA", "opa"),
        startup_timeout=startup_timeout,
        base_url=env.get("SHIM_BASE_URL", f"http://localhost:{port}").rstrip("/"),
    )


def check_data(path: Path) -> None:
    """Check that the policy data file is a JSON object.

    OPA would start without the file, or with data under another path, and
    then deny every request; failing here names the cause.

    Args:
        path: The policy data file.

    Raises:
        ConfigError: If the file is missing, unreadable, not JSON or not an
            object.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"policy data {path} not found (mount it, or set TES_AUTHZ_DATA)") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"policy data {path} is unreadable: {exc}") from None
    except ValueError as exc:
        raise ConfigError(f"policy data {path} is not JSON: {exc}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"policy data {path} is not a JSON object")


def opa_command(settings: Settings) -> list[str]:
    """Build the command line of OPA.

    OPA listens on loopback only. The data file is loaded under the path
    ``tes_authz`` (``<path>:<file>``), whatever its file name. Hidden files
    and directories (e.g. the ``..data`` links of Kubernetes ConfigMap
    volumes) are ignored, so that nothing is loaded twice.

    Args:
        settings: The settings.

    Returns:
        The command line.
    """
    return [
        settings.opa,
        "run",
        "--server",
        f"--addr=127.0.0.1:{settings.opa_port}",
        "--log-level=info",
        "--ignore=.*",
        str(settings.policy),
        f"tes_authz:{settings.data}",
    ]


def wait_for_opa(url: str, process: subprocess.Popen[bytes], timeout: float) -> None:
    """Wait until OPA answers its health check.

    Args:
        url: Base URL of OPA.
        process: The OPA process.
        timeout: Seconds to wait.

    Raises:
        ConfigError: If OPA exits or isn't healthy in time.
    """
    deadline = time.monotonic() + timeout
    while True:
        if process.poll() is not None:
            raise ConfigError(f"OPA exited with status {process.returncode} during startup")
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=1) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            pass
        if time.monotonic() >= deadline:
            raise ConfigError(f"OPA not healthy after {timeout:g} s")
        time.sleep(0.2)


def make_server(settings: Settings) -> ThreadingHTTPServer:
    """Build the AuthZEN front for the OPA of these settings.

    The front's decision function asks OPA at ``opa_front.OPA_URL``, which
    is set to OPA's loopback URL here (``OPA_URL`` of the environment is not
    used).

    Args:
        settings: The settings.

    Returns:
        The bound, not yet serving, server.
    """
    opa_front.OPA_URL = settings.opa_url
    metadata: dict[str, Any] = {
        "policy_decision_point": settings.base_url,
        "access_evaluation_endpoint": settings.base_url + "/access/v1/evaluation",
    }
    return ThreadingHTTPServer((settings.host, settings.port), make_handler(opa_front.decide, metadata))


def run(settings: Settings) -> int:
    """Run OPA and the front until a signal or until OPA exits.

    Args:
        settings: The settings.

    Returns:
        The exit status: 0 after ``SIGTERM`` or ``SIGINT``, 1 if OPA exited
        on its own.

    Raises:
        ConfigError: If the policy data is unusable or OPA doesn't start.
    """
    check_data(settings.data)
    if not settings.policy.is_dir():
        raise ConfigError(f"policy directory {settings.policy} not found")
    stopping = threading.Event()
    process = subprocess.Popen(opa_command(settings))  # noqa: S603 (fixed arguments)

    def stop(signum: int, frame: FrameType | None) -> None:
        stopping.set()
        if process.poll() is None:
            process.terminate()

    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    server: ThreadingHTTPServer | None = None
    try:
        try:
            wait_for_opa(settings.opa_url, process, settings.startup_timeout)
        except ConfigError:
            if stopping.is_set():  # stopped during startup
                return 0
            raise
        if stopping.is_set():
            return 0
        server = make_server(settings)
        threading.Thread(target=server.serve_forever, name="front", daemon=True).start()
        log.info("OPA ready; front listening on %s:%d", settings.host, settings.port)
        status = process.wait()
        if stopping.is_set():
            return 0
        log.error("OPA exited with status %s; stopping", status)
        return 1
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main() -> None:
    """Run the service; exit with status 2 on unusable settings."""
    logging.basicConfig(level=os.environ.get("SHIM_LOG_LEVEL", "INFO"))
    try:
        sys.exit(run(load_settings(os.environ)))
    except ConfigError as exc:
        log.error("%s", exc)
        sys.exit(2)


if __name__ == "__main__":
    main()

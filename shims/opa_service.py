"""The OPA decision service of the container image: OPA and its front in one.

The image (``Dockerfile``) runs this module as its entry point. It starts
OPA with the policy baked into the image and the operator's policy data,
bound to loopback (which all containers of a pod share) and answering only
the decision query and the health check (``--authorization=basic`` with the
API policy ``engines/opa/system/authz.rego``), so that nobody can change or
read policy and data through OPA's API; waits until OPA is healthy; then
serves the AuthZEN front (``opa_front.decide`` behind
``common.make_handler``) on ``TES_AUTHZ_HOST``:``TES_AUTHZ_PORT``. If OPA
exits, the front stops and the process exits with status 1, so that the
container restarts instead of answering ``502`` for good. Unusable settings
or data, and a taken front port, exit with status 2. ``SIGTERM`` and
``SIGINT`` stop the front first, then OPA, with status 0.

Settings (environment):
    TES_AUTHZ_DATA: Policy data file, a JSON object (default
        ``/etc/tes-authz/data.json``); loaded as ``data.tes_authz``.
    TES_AUTHZ_POLICY: Directory of the Rego policy (default
        ``/opt/tes-authz/policy``, the policy of the image).
    TES_AUTHZ_SYSTEM_POLICY: Directory of the policy of OPA's own API
        (default ``/opt/tes-authz/system``, the image's
        ``engines/opa/system/authz.rego``: only the decision query and the
        health check).
    TES_AUTHZ_HOST: Address of the front (default ``0.0.0.0``; ``127.0.0.1``
        for a sidecar that only its pod may reach).
    TES_AUTHZ_PORT: Port of the front (default ``8080``).
    TES_AUTHZ_OPA_PORT: Loopback port of OPA (default ``8181``).
    TES_AUTHZ_OPA: OPA executable (default ``opa``, on ``PATH``).
    TES_AUTHZ_STARTUP_TIMEOUT: Seconds to wait for OPA (default ``30``).
    SHIM_BASE_URL: Base URL served in ``/.well-known/authzen-configuration``
        (default ``http://localhost:<port>``).
    SHIM_TIMEOUT, SHIM_LOG_LEVEL, SHIM_MAX_BODY_BYTES: As for the front;
        checked here, so that bad values exit with status 2.

``OPA_URL`` and ``OPA_DECISION_PATH`` of the front are not used: the front
asks this OPA for ``tes/authz/allow``, the only query that OPA's API
policy allows.
"""

from __future__ import annotations

import json
import logging
import math
import os
import signal
import socket
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

log = logging.getLogger("tes-authz-service")

DECISION_PATH = "tes/authz/allow"
"""Data API path of the decision, as allowed by OPA's API policy."""


class ConfigError(ValueError):
    """Raised when the settings or the policy data are unusable."""


@dataclass(frozen=True)
class Settings:
    """Settings of the service, from the environment.

    Attributes:
        data: Policy data file.
        policy: Directory of the Rego policy.
        system_policy: Directory of the policy of OPA's own API.
        host: Address of the front.
        port: Port of the front.
        opa_port: Loopback port of OPA.
        opa: OPA executable.
        startup_timeout: Seconds to wait for OPA.
        base_url: Base URL for the AuthZEN metadata.
    """

    data: Path
    policy: Path
    system_policy: Path
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


def _check_front_settings(env: Mapping[str, str]) -> None:
    """Check the settings that the front's modules read at import.

    Args:
        env: The environment.

    Raises:
        ConfigError: If one is invalid.
    """
    raw = env.get("SHIM_TIMEOUT", "1.5")
    try:
        timeout = float(raw)
    except ValueError:
        raise ConfigError(f"SHIM_TIMEOUT is not a number: {raw!r}") from None
    if not (timeout > 0 and math.isfinite(timeout)):
        raise ConfigError(f"SHIM_TIMEOUT must be positive and finite: {raw!r}")
    raw = env.get("SHIM_MAX_BODY_BYTES", "1048576")
    try:
        size = int(raw)
    except ValueError:
        raise ConfigError(f"SHIM_MAX_BODY_BYTES is not an integer: {raw!r}") from None
    if size < 1:
        raise ConfigError(f"SHIM_MAX_BODY_BYTES must be positive: {raw!r}")
    level = env.get("SHIM_LOG_LEVEL", "INFO")
    if not isinstance(logging.getLevelNamesMapping().get(level), int):
        raise ConfigError(f"SHIM_LOG_LEVEL is not a log level: {level!r}")


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
    if not (startup_timeout > 0 and math.isfinite(startup_timeout)):
        raise ConfigError(f"TES_AUTHZ_STARTUP_TIMEOUT must be positive and finite: {raw_timeout!r}")
    _check_front_settings(env)
    host = env.get("TES_AUTHZ_HOST", "0.0.0.0")  # noqa: S104 (inside a container)
    if not host:
        raise ConfigError("TES_AUTHZ_HOST is empty")
    return Settings(
        data=Path(env.get("TES_AUTHZ_DATA", "/etc/tes-authz/data.json")),
        policy=Path(env.get("TES_AUTHZ_POLICY", "/opt/tes-authz/policy")),
        system_policy=Path(env.get("TES_AUTHZ_SYSTEM_POLICY", "/opt/tes-authz/system")),
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

    OPA listens on loopback only, and its API answers only what the API
    policy (``system_policy``, ``--authorization=basic``) allows: the
    decision query and the health check, so that no other container of a
    pod (which shares the loopback) can change or read policy and data.
    The data file is loaded under the path
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
        "--authorization=basic",
        "--log-level=info",
        "--ignore=.*",
        str(settings.policy),
        str(settings.system_policy),
        f"tes_authz:{settings.data}",
    ]


def wait_for_opa(
    url: str, process: subprocess.Popen[bytes], timeout: float, stopping: threading.Event | None = None
) -> None:
    """Wait until OPA answers its health check, or until a stop.

    Args:
        url: Base URL of OPA.
        process: The OPA process.
        timeout: Seconds to wait.
        stopping: Set when the service is to stop; returns at once then.

    Raises:
        ConfigError: If OPA exits or isn't healthy in time.
    """
    deadline = time.monotonic() + timeout
    while stopping is None or not stopping.is_set():
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

    The front's modules read ``SHIM_*`` settings at import, so they are
    imported here, after ``load_settings`` checked them. The front asks this
    OPA (``OPA_URL``) for ``DECISION_PATH``, whatever the environment says.

    Args:
        settings: The settings.

    Returns:
        The bound, not yet serving, server.

    Raises:
        ConfigError: If the front's address can't be bound (e.g. the port
            is taken by another container of the pod).
    """
    import opa_front
    from common import make_handler

    opa_front.OPA_URL = settings.opa_url
    opa_front.DECISION_PATH = DECISION_PATH
    metadata: dict[str, Any] = {
        "policy_decision_point": settings.base_url,
        "access_evaluation_endpoint": settings.base_url + "/access/v1/evaluation",
    }
    try:
        server = ThreadingHTTPServer((settings.host, settings.port), make_handler(opa_front.decide, metadata))
    except OSError as exc:
        raise ConfigError(f"front can't listen on {settings.host}:{settings.port}: {exc}") from None
    # `server_close()` then waits for requests in progress (bounded by the
    # socket and OPA timeouts), so that OPA is stopped only after them
    server.daemon_threads = False
    return server


def check_port_free(port: int) -> None:
    """Check that nothing listens on OPA's loopback port yet.

    Otherwise the health check could be answered by another process (e.g.
    another OPA of the pod), and the front would send decisions there.

    Args:
        port: OPA's loopback port.

    Raises:
        ConfigError: If the port is taken.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as exc:
            raise ConfigError(f"OPA's port 127.0.0.1:{port} is taken (TES_AUTHZ_OPA_PORT): {exc}") from None


def run(settings: Settings) -> int:
    """Run OPA and the front until a signal or until OPA exits.

    Args:
        settings: The settings.

    Returns:
        The exit status: 0 after ``SIGTERM`` or ``SIGINT``, 1 if OPA exited
        on its own.

    Raises:
        ConfigError: If the policy data is unusable, OPA's port is taken,
            or OPA doesn't start.
    """
    stopping = threading.Event()

    # Only flags the stop: the main thread then stops the front first and
    # OPA last, so that no request reaches the front without OPA behind it.
    # Installed first, so that a stop during startup is handled too
    def stop(signum: int, frame: FrameType | None) -> None:
        stopping.set()

    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    process: subprocess.Popen[bytes] | None = None
    server: ThreadingHTTPServer | None = None
    serving = False
    try:
        check_data(settings.data)
        for directory in (settings.policy, settings.system_policy):
            if not directory.is_dir():
                raise ConfigError(f"policy directory {directory} not found")
        check_port_free(settings.opa_port)
        if stopping.is_set():
            return 0
        try:
            process = subprocess.Popen(opa_command(settings))  # noqa: S603 (fixed arguments)
        except OSError as exc:
            raise ConfigError(f"OPA can't be started ({settings.opa}): {exc}") from None
        wait_for_opa(settings.opa_url, process, settings.startup_timeout, stopping)
        if stopping.is_set():  # stopped during startup
            return 0
        server = make_server(settings)
        threading.Thread(target=server.serve_forever, name="front", daemon=True).start()
        serving = True
        log.info("OPA ready; front listening on %s:%d", settings.host, settings.port)
        while not stopping.wait(0.2):
            if process.poll() is not None:
                log.error("OPA exited with status %s; stopping", process.returncode)
                return 1
        return 0
    finally:
        if server is not None:
            if serving:  # `shutdown()` would wait forever otherwise
                server.shutdown()
            server.server_close()
        if process is not None and process.poll() is None:
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
    try:
        settings = load_settings(os.environ)
    except ConfigError as exc:
        logging.basicConfig(level="INFO")
        log.error("%s", exc)
        sys.exit(2)
    logging.basicConfig(level=os.environ.get("SHIM_LOG_LEVEL", "INFO"))
    try:
        sys.exit(run(settings))
    except ConfigError as exc:
        log.error("%s", exc)
        sys.exit(2)


if __name__ == "__main__":
    main()

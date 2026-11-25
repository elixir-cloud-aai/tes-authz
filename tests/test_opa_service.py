"""The entry point of the container image (`shims/opa_service.py`).

The settings, the data check and OPA's command line are tested directly;
the process supervision runs the module as the image does, with
`tests/fake_opa.py` in place of OPA, so that no container is needed.
"""

from __future__ import annotations

import copy
import json
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import opa_service
import pytest

from .conftest import http

ROOT = Path(__file__).resolve().parent.parent
SERVICE = ROOT / "shims" / "opa_service.py"
FAKE_OPA = Path(__file__).resolve().parent / "fake_opa.py"
REQUEST = json.loads((ROOT / "golden" / "requests" / "create-member-exact.json").read_text())["request"]


Start = Callable[[dict[str, str]], "subprocess.Popen[bytes]"]
"""Starts the service with an environment (fixture ``start``)."""


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# Settings


def test_defaults_are_those_of_the_image():
    """Without settings, the paths and ports are those of the Dockerfile."""
    settings = opa_service.load_settings({})
    assert settings.data == Path("/etc/tes-authz/data.json")
    assert settings.policy == Path("/opt/tes-authz/policy")
    assert settings.system_policy == Path("/opt/tes-authz/system")
    assert (settings.host, settings.port, settings.opa_port) == ("0.0.0.0", 8080, 8181)
    assert settings.opa == "opa"
    assert settings.startup_timeout == 30
    assert settings.base_url == "http://localhost:8080"
    assert settings.opa_url == "http://127.0.0.1:8181"


def test_settings_from_the_environment():
    """Every setting is read from its variable; the base URL loses a trailing slash."""
    settings = opa_service.load_settings(
        {
            "TES_AUTHZ_DATA": "/d/x.json",
            "TES_AUTHZ_POLICY": "/p",
            "TES_AUTHZ_SYSTEM_POLICY": "/s",
            "TES_AUTHZ_HOST": "127.0.0.1",
            "TES_AUTHZ_PORT": "9000",
            "TES_AUTHZ_OPA_PORT": "9001",
            "TES_AUTHZ_OPA": "/bin/opa",
            "TES_AUTHZ_STARTUP_TIMEOUT": "2.5",
            "SHIM_BASE_URL": "http://tes-authz:9000/",
        }
    )
    assert settings == opa_service.Settings(
        data=Path("/d/x.json"),
        policy=Path("/p"),
        system_policy=Path("/s"),
        host="127.0.0.1",
        port=9000,
        opa_port=9001,
        opa="/bin/opa",
        startup_timeout=2.5,
        base_url="http://tes-authz:9000",
    )


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"TES_AUTHZ_PORT": "http"}, "TES_AUTHZ_PORT is not a port"),
        ({"TES_AUTHZ_PORT": "0"}, "TES_AUTHZ_PORT is not a port"),
        ({"TES_AUTHZ_OPA_PORT": "65536"}, "TES_AUTHZ_OPA_PORT is not a port"),
        ({"TES_AUTHZ_PORT": "8181"}, "must differ"),
        ({"TES_AUTHZ_STARTUP_TIMEOUT": "soon"}, "not a number"),
        ({"TES_AUTHZ_STARTUP_TIMEOUT": "0"}, "must be positive"),
        ({"TES_AUTHZ_STARTUP_TIMEOUT": "nan"}, "must be positive"),
        ({"TES_AUTHZ_HOST": ""}, "TES_AUTHZ_HOST is empty"),
        ({"SHIM_TIMEOUT": "abc"}, "SHIM_TIMEOUT is not a number"),
        ({"SHIM_TIMEOUT": "-1"}, "SHIM_TIMEOUT must be positive"),
        ({"SHIM_MAX_BODY_BYTES": "1.5"}, "SHIM_MAX_BODY_BYTES is not an integer"),
        ({"SHIM_MAX_BODY_BYTES": "0"}, "SHIM_MAX_BODY_BYTES must be positive"),
        ({"SHIM_LOG_LEVEL": "verbose"}, "SHIM_LOG_LEVEL is not a log level"),
    ],
)
def test_invalid_settings_are_refused(env: dict[str, str], message: str):
    """Unusable settings raise a ConfigError that names the variable."""
    with pytest.raises(opa_service.ConfigError, match=message):
        opa_service.load_settings(env)


# Policy data


def test_data_must_be_a_json_object(tmp_path: Path):
    """The data file must exist and hold a JSON object."""
    path = tmp_path / "data.json"
    with pytest.raises(opa_service.ConfigError, match="not found"):
        opa_service.check_data(path)
    path.write_text("{")
    with pytest.raises(opa_service.ConfigError, match="not JSON"):
        opa_service.check_data(path)
    path.write_text("[]")
    with pytest.raises(opa_service.ConfigError, match="not a JSON object"):
        opa_service.check_data(path)
    path.write_bytes(b"\xff")
    with pytest.raises(opa_service.ConfigError, match="unreadable"):
        opa_service.check_data(path)
    with pytest.raises(opa_service.ConfigError, match="unreadable"):
        opa_service.check_data(tmp_path)
    path.write_text("{}")
    opa_service.check_data(path)


def test_reference_policy_data_passes():
    """The reference policy data, which operators copy, passes the check."""
    opa_service.check_data(ROOT / "config" / "reference-policy.json")


# OPA's command line


def test_opa_listens_on_loopback_and_loads_data_as_tes_authz():
    """OPA binds to loopback, guards its API, skips hidden files, loads the data as `tes_authz`."""
    settings = opa_service.load_settings({"TES_AUTHZ_OPA_PORT": "9181", "TES_AUTHZ_DATA": "/etc/x/my.json"})
    assert opa_service.opa_command(settings) == [
        "opa",
        "run",
        "--server",
        "--addr=127.0.0.1:9181",
        "--authorization=basic",
        "--log-level=info",
        "--ignore=.*",
        "/opt/tes-authz/policy",
        "/opt/tes-authz/system",
        "tes_authz:/etc/x/my.json",
    ]


# The process, with a fake OPA


@pytest.fixture
def service_env(tmp_path: Path) -> dict[str, str]:
    """Environment for running the service with the fake OPA."""
    fake = tmp_path / "opa"
    fake.write_text(f"#!{sys.executable}\nimport runpy\nrunpy.run_path({str(FAKE_OPA)!r}, run_name='__main__')\n")
    fake.chmod(0o755)
    (tmp_path / "policy").mkdir()
    (tmp_path / "system").mkdir()
    (tmp_path / "data.json").write_text("{}")
    port = _free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("TES_AUTHZ_", "SHIM_", "FAKE_OPA_"))}
    env.update(
        {
            "TES_AUTHZ_OPA": str(fake),
            "TES_AUTHZ_POLICY": str(tmp_path / "policy"),
            "TES_AUTHZ_SYSTEM_POLICY": str(tmp_path / "system"),
            "OPA_DECISION_PATH": "not/used",
            "TES_AUTHZ_DATA": str(tmp_path / "data.json"),
            "TES_AUTHZ_HOST": "127.0.0.1",
            "TES_AUTHZ_PORT": str(port),
            "TES_AUTHZ_OPA_PORT": str(_free_port()),
            "TES_AUTHZ_STARTUP_TIMEOUT": "10",
            "FAKE_OPA_ARGS": str(tmp_path / "args.json"),
            "PYTHONPATH": str(ROOT / "shims"),
        }
    )
    return env


@pytest.fixture
def start() -> Iterator[Start]:
    """Start the service as the image does; stop it after the test."""
    processes: list[subprocess.Popen[bytes]] = []

    def _start(env: dict[str, str]) -> subprocess.Popen[bytes]:
        process = subprocess.Popen([sys.executable, str(SERVICE)], env=env, start_new_session=True)
        processes.append(process)
        return process

    yield _start
    for process in processes:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def _wait_for_front(url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        assert process.poll() is None, f"service exited with {process.returncode}"
        try:
            if http("GET", f"{url}/health", timeout=1)[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.1)
    pytest.fail("front not ready after 15 s")


def _opa_pid(process: subprocess.Popen[bytes]) -> int:
    children = Path(f"/proc/{process.pid}/task/{process.pid}/children")
    if not children.exists():
        pytest.skip("needs /proc (Linux)")
    pids = children.read_text().split()
    assert len(pids) == 1, pids
    return int(pids[0])


def test_front_answers_with_opas_decision_and_stops_on_sigterm(service_env: dict[str, str], start: Start):
    """The front serves OPA's decisions; SIGTERM stops OPA and the service with 0."""
    process = start(service_env)
    url = f"http://127.0.0.1:{service_env['TES_AUTHZ_PORT']}"
    _wait_for_front(url, process)
    allowed = copy.deepcopy(REQUEST)
    allowed["subject"]["id"] = "allowed"
    assert http("POST", f"{url}/access/v1/evaluation", allowed) == (200, {"decision": True})
    assert http("POST", f"{url}/access/v1/evaluation", REQUEST) == (200, {"decision": False})
    status, metadata = http("GET", f"{url}/.well-known/authzen-configuration")
    assert status == 200
    assert (
        metadata["access_evaluation_endpoint"]
        == f"http://localhost:{service_env['TES_AUTHZ_PORT']}/access/v1/evaluation"
    )
    args = json.loads(Path(service_env["FAKE_OPA_ARGS"]).read_text())
    assert args[-1] == f"tes_authz:{service_env['TES_AUTHZ_DATA']}"
    opa_pid = _opa_pid(process)
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=15) == 0
    # The service has terminated and reaped OPA
    with pytest.raises(ProcessLookupError):
        os.kill(opa_pid, 0)


def test_service_exits_with_1_when_opa_dies(service_env: dict[str, str], start: Start):
    """If OPA exits on its own, the service exits with 1 (the container restarts)."""
    process = start(service_env)
    _wait_for_front(f"http://127.0.0.1:{service_env['TES_AUTHZ_PORT']}", process)
    os.kill(_opa_pid(process), signal.SIGKILL)
    assert process.wait(timeout=15) == 1


def test_service_exits_with_2_when_opa_fails_to_start(service_env: dict[str, str], start: Start):
    """If OPA exits during startup, the service exits with 2."""
    process = start({**service_env, "FAKE_OPA_EXIT": "1"})
    assert process.wait(timeout=15) == 2


def test_service_exits_with_2_without_data(service_env: dict[str, str], start: Start, tmp_path: Path):
    """Without the data file, the service exits with 2 before starting OPA."""
    process = start({**service_env, "TES_AUTHZ_DATA": str(tmp_path / "missing.json")})
    assert process.wait(timeout=15) == 2
    assert not Path(service_env["FAKE_OPA_ARGS"]).exists(), "OPA was started"


def test_service_exits_with_2_without_policy(service_env: dict[str, str], start: Start, tmp_path: Path):
    """Without the policy directory, the service exits with 2 before starting OPA."""
    process = start({**service_env, "TES_AUTHZ_POLICY": str(tmp_path / "missing")})
    assert process.wait(timeout=15) == 2
    assert not Path(service_env["FAKE_OPA_ARGS"]).exists(), "OPA was started"


def test_service_exits_with_2_on_invalid_settings(service_env: dict[str, str], start: Start):
    """Invalid settings make the service exit with 2."""
    process = start({**service_env, "TES_AUTHZ_PORT": "http"})
    assert process.wait(timeout=15) == 2


def test_service_stops_on_sigint(service_env: dict[str, str], start: Start):
    """SIGINT stops the service with 0, as SIGTERM does."""
    process = start(service_env)
    _wait_for_front(f"http://127.0.0.1:{service_env['TES_AUTHZ_PORT']}", process)
    process.send_signal(signal.SIGINT)
    assert process.wait(timeout=15) == 0


def test_service_exits_with_2_when_opa_never_gets_healthy(service_env: dict[str, str], start: Start):
    """If OPA isn't healthy within the startup timeout, the service exits with 2."""
    process = start({**service_env, "FAKE_OPA_UNHEALTHY": "1", "TES_AUTHZ_STARTUP_TIMEOUT": "1"})
    assert process.wait(timeout=15) == 2


def test_sigterm_during_startup_stops_with_0(service_env: dict[str, str], start: Start):
    """A SIGTERM before OPA is healthy stops the service with 0, without serving."""
    process = start({**service_env, "FAKE_OPA_UNHEALTHY": "1"})
    args = Path(service_env["FAKE_OPA_ARGS"])
    deadline = time.monotonic() + 15
    while not args.exists():  # OPA started, the service waits for it
        assert time.monotonic() < deadline, "OPA not started"
        time.sleep(0.05)
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=15) == 0
    with pytest.raises(OSError):
        http("GET", f"http://127.0.0.1:{service_env['TES_AUTHZ_PORT']}/health", timeout=1)


def test_service_exits_with_2_when_the_port_is_taken(service_env: dict[str, str], start: Start):
    """If the front's port is taken (e.g. by the TES in the pod), the service exits with 2."""
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", int(service_env["TES_AUTHZ_PORT"])))
        taken.listen()
        process = start(service_env)
        assert process.wait(timeout=15) == 2


def test_service_exits_with_2_on_invalid_front_settings(service_env: dict[str, str], start: Start):
    """Invalid settings of the front's modules exit with 2 too, not with a traceback."""
    process = start({**service_env, "SHIM_LOG_LEVEL": "verbose"})
    assert process.wait(timeout=15) == 2

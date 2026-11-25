"""The container image of the OPA decision service (`Dockerfile`).

The static checks run with the unit tests. The replay of the golden
requests needs a container of the image, which `scripts/test-image.sh`
starts and announces in `TES_AUTHZ_IMAGE_URL`.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
import yaml

from harness.golden import GoldenCase, load_cases

from .conftest import http

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"
PINNED = re.compile(r"docker\.io/(?:library/)?(?P<name>[^:@]+):(?P<tag>[^@\s]+)@sha256:[0-9a-f]{64}")


def _instructions() -> list[tuple[str, str]]:
    """Return the Dockerfile's instructions as (keyword, arguments), lines joined."""
    text = re.sub(r"\\\n", " ", DOCKERFILE.read_text())
    lines = [line.strip() for line in text.splitlines()]
    return [
        (line.split(None, 1)[0].upper(), line.split(None, 1)[1]) for line in lines if line and not line.startswith("#")
    ]


def _compose_images() -> dict[str, str]:
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    return {name: service["image"] for name, service in compose["services"].items() if "image" in service}


def _base_images() -> list[re.Match[str]]:
    images = []
    for keyword, args in _instructions():
        if keyword == "FROM":
            match = PINNED.match(args.split()[0])
            assert match, f"base image not pinned by digest: {args}"
            images.append(match)
    return images


def test_base_images_are_pinned_and_match_compose():
    """OPA and Python have the versions that CI tests in compose."""
    opa, python = _base_images()
    compose = _compose_images()
    assert f"{opa['name']}:{opa['tag']}" == compose["opa"] + "-static", "bump with compose.yaml"
    assert f"{python['name']}:{python['tag']}" == compose["opa-front"], "bump with compose.yaml"


def test_image_runs_the_service_as_nobody_without_pip():
    """Non-root (numeric), pip removed, the service as entry point, policy checked."""
    instructions = _instructions()
    assert ("USER", "65534:65534") in instructions
    assert ("ENTRYPOINT", '["python", "/opt/tes-authz/opa_service.py"]') in instructions
    runs = " ".join(args for keyword, args in instructions if keyword == "RUN")
    assert "pip uninstall --yes" in runs
    assert "opa check --strict /opt/tes-authz/policy" in runs


def test_copied_files_exist_and_are_the_only_build_context():
    """Every COPY source exists and `.dockerignore` re-includes exactly those."""
    sources: list[str] = []
    for keyword, args in _instructions():
        if keyword == "COPY" and not args.startswith("--from="):
            sources.extend(args.split()[:-1])
    for source in sources:
        assert (ROOT / source).exists(), source
    lines = [line.strip() for line in DOCKERIGNORE.read_text().splitlines()]
    lines = [line for line in lines if line and not line.startswith("#")]
    assert lines[0] == "*"
    assert sorted(line[1:] for line in lines if line.startswith("!")) == sorted(sources)
    # The secret patterns come last, so that no re-include overrides them
    last_include = max(i for i, line in enumerate(lines) if line.startswith("!"))
    assert lines.index("**/.env*") > last_include


@pytest.fixture(scope="module")
def image_url() -> str:
    """The evaluation URL of a running container of the image, or skip."""
    url = os.environ.get("TES_AUTHZ_IMAGE_URL")
    if not url:
        pytest.skip("TES_AUTHZ_IMAGE_URL not set (run scripts/test-image.sh)")
    return url


CASES = [c for c in load_cases() if "reference_policy" in c.expect]


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_image_gives_golden_decisions(image_url: str, case: GoldenCase):
    """A container of the image answers every golden request as expected."""
    status, body = http("POST", image_url, case.request, {"X-Request-ID": f"image-{case.name}"})
    assert status == 200, f"answered {status}: {body}"
    assert isinstance(body, dict) and body.get("decision") is case.expect["reference_policy"], case.description

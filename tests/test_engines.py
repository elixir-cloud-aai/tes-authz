"""Engine conformance (layer 2): replay the golden requests against each engine."""

from __future__ import annotations

import pytest

from harness.engines import ENGINES, OPA_DATA_API, Engine
from harness.golden import GoldenCase, load_cases

from .conftest import http

pytestmark = pytest.mark.services

CASES = load_cases()
TARGETS = [*ENGINES.values(), OPA_DATA_API]


def _decide(engine: Engine, case: GoldenCase) -> bool:
    if engine.authzen:
        status, body = http("POST", engine.host_url, case.request, {"X-Request-ID": f"golden-{case.name}"})
        assert status == 200, f"{engine.name} answered {status}: {body}"
        assert isinstance(body, dict) and isinstance(body.get("decision"), bool), body
        return bool(body["decision"])
    status, body = http("POST", engine.host_url, {"input": case.request})
    assert status == 200, f"{engine.name} answered {status}: {body}"
    assert isinstance(body.get("result"), bool), body
    return bool(body["result"])


@pytest.mark.parametrize("engine", TARGETS, ids=[t.name for t in TARGETS])
@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_golden_decision(services, engine: Engine, case: GoldenCase):
    """The engine gives the expected decision for the golden request."""
    if engine.policy not in case.expect:
        pytest.skip(f"no {engine.policy} expectation for {case.name}")
    assert _decide(engine, case) is case.expect[engine.policy], case.description

"""Network checks of the Kubernetes deployment, run in a client pod.

`scripts/test-kubernetes.sh` pipes this file into `python -` in a pod with
or without the NetworkPolicy's label `tes-authz/client: "true"`:

    python - labelled|unlabelled <pod IP of the decision service>

A labelled client must reach the Service and an unlabelled one must not
(given a network plugin that enforces NetworkPolicies, as kind's does);
neither may reach OPA's Data API on the pod IP, as OPA listens on the pod's
loopback only. Exits non-zero on the first failed check.
"""

from __future__ import annotations

import sys
import urllib.request

SERVICE_HEALTH = "http://tes-authz:8080/health"
"""Health endpoint of the front, through the Service."""


def reachable(url: str) -> bool:
    """Return whether a GET of the URL answers 200 within 5 seconds.

    Args:
        url: The URL to get.

    Returns:
        Whether the URL answered 200.
    """
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return bool(response.status == 200)
    except OSError:
        return False


def main(argv: list[str]) -> int:
    """Run the checks for one client.

    Args:
        argv: The client kind (`labelled` or `unlabelled`) and the pod IP.

    Returns:
        0 if all checks passed, else 1.
    """
    kind, pod_ip = argv
    labelled = kind == "labelled"
    if reachable(SERVICE_HEALTH) is not labelled:
        print(f"[FAIL] {kind} client: Service reachable is {not labelled}")
        return 1
    print(f"[ok] {kind} client {'reaches' if labelled else 'does not reach'} the Service")
    if reachable(f"http://{pod_ip}:8181/health"):
        print(f"[FAIL] {kind} client reaches OPA's Data API on the pod IP")
        return 1
    print(f"[ok] {kind} client does not reach OPA on the pod IP")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

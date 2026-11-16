"""Generate the phase-1 golden AuthZEN requests and URL stripping cases.

Until the Poiesis hook writes golden requests from its own tests
(``tes-authz/golden/``), these files stand in for them: one file per
conformance case that reaches the decision service, each with the decision
the reference policy (``config/reference-policy.json``) must give.

Usage: ``python scripts/gen_golden.py [--check]``. ``--check`` exits 1 if
the committed files differ from what the generator produces.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "golden"
SERVICE = "tes-authz-test"
ISS = "https://login.aai.lifescience-ri.eu/oidc/"
VO = "urn:geant:lifescience-ri.eu:group:example-vo"
AUTH = "#login.aai.lifescience-ri.eu"

GROUP = VO + AUTH
SUBGROUP = VO + ":analysts" + AUTH
ADMIN = VO + ":tes-admins" + AUTH
NEAR_MISS = "urn:geant:lifescience-ri.eu:group:example-vox" + AUTH
OTHER_VO = "urn:geant:lifescience-ri.eu:group:other-vo:sub" + AUTH
LONG_SUB = "x" * 600
MULTI_ISSUER_ID = f"{ISS}|abc123@lifescience-ri.eu"


def subject(
    sub: str,
    entitlements: Any = None,
    *,
    owner_id: str | None = None,
    client_id: str = "tes-client",
    claims: bool = True,
) -> dict[str, Any]:
    """Build a profile subject.

    Args:
        sub: The OIDC ``sub``.
        entitlements: The ``eduperson_entitlement`` claim value; ``None``
            leaves the claim out.
        owner_id: The owner ID if it differs from ``sub``.
        client_id: The client ID.
        claims: Whether to send a ``claims`` object at all.

    Returns:
        The subject object.
    """
    props: dict[str, Any] = {
        "iss": ISS,
        "sub": sub,
        "client_id": client_id,
        "scope": ["openid", "eduperson_entitlement"],
    }
    props["claims"] = {} if entitlements is None or not claims else {"eduperson_entitlement": entitlements}
    return {"type": "user", "id": owner_id or sub, "properties": props}


ALICE = subject("alice-sub", [SUBGROUP, OTHER_VO])
BOB = subject("bob-sub", [GROUP])
CAROL = subject("carol-sub", [NEAR_MISS, OTHER_VO])
DAVE = subject("dave-sub", [ADMIN])
FRANK = subject("frank-sub")
SERVICE_CLIENT = subject("service-account-proxy", None, client_id="protes", claims=False)
SERVICE_CLIENT["properties"]["scope"] = ["openid"]

TASK = {
    "name": "hello",
    "tags": {"project": "demo"},
    "resources": {"cpu_cores": 1, "ram_gb": 1.0, "disk_gb": 5.0, "preemptible": False, "zones": []},
    "volumes": ["/vol/a"],
    "executors": [{"image": "docker.io/library/alpine:3.20"}],
    "inputs": [{"url": "s3://bucket/in.txt", "path": "/data/in.txt", "type": "FILE"}],
    "outputs": [{"url": "https://storage.example.org/out/", "path": "/data/out", "type": "DIRECTORY"}],
}


def request(
    subj: dict[str, Any],
    action: str,
    rtype: str,
    rid: str,
    rprops: dict[str, Any] | None = None,
    aprops: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a profile request.

    Args:
        subj: The subject.
        action: The action name.
        rtype: The resource type.
        rid: The resource ID.
        rprops: Resource properties (``None``: no ``properties`` key, as on
            ``ListTasks`` sets; ``{}`` for a missing task, spec section 3.7).
        aprops: Action properties (always sent; ``{}`` when ``None``).
        context: Replacement for the default context.

    Returns:
        The AuthZEN request.
    """
    resource: dict[str, Any] = {"type": rtype, "id": rid}
    if rprops is not None:
        resource["properties"] = rprops
    act: dict[str, Any] = {"name": action, "properties": {} if aprops is None else aprops}
    ctx = context if context is not None else {"tes": {"profile": "tes-authzen/1", "service_id": SERVICE}}
    return {"subject": subj, "action": act, "resource": resource, "context": ctx}


def create(
    subj: dict[str, Any], task: dict[str, Any] | None = None, set_id: str = "own", context: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Build a CreateTask request.

    Args:
        subj: The subject.
        task: The task projection (default ``TASK``).
        set_id: The task set.
        context: Replacement for the default context.

    Returns:
        The AuthZEN request.
    """
    return request(
        subj, "CreateTask", "tes_task_set", set_id, {"task": TASK if task is None else task}, {}, context=context
    )


def task_meta(owner: str | None) -> dict[str, Any]:
    """Build stored-task properties.

    Args:
        owner: The owner, or ``None`` for a task without an exact owner.

    Returns:
        The resource properties.
    """
    props: dict[str, Any] = {"state": "RUNNING", "tags": {"project": "demo"}}
    if owner is not None:
        props["owner"] = owner
    return props


def with_images(*images: str) -> dict[str, Any]:
    """Return ``TASK`` with other executor images.

    Args:
        *images: The images.

    Returns:
        The task projection.
    """
    return {**TASK, "executors": [{"image": image} for image in images]}


def cases() -> list[tuple[str, str, str, dict[str, Any], bool]]:
    """List the golden cases.

    Returns:
        Tuples of name, spec case, description, request and expected decision.
    """
    view = {"view": "MINIMAL"}
    long = subject(LONG_SUB, [GROUP])
    multi = subject("abc123@lifescience-ri.eu", [SUBGROUP], owner_id=MULTI_ISSUER_ID)
    erin = subject("erin-sub", SUBGROUP)
    mixed = subject("gina-sub", [42, {"x": 1}, GROUP])
    number = subject("hank-sub", 42)
    parent = subject("ivan-sub", [VO])
    bad_type = {**ALICE, "type": "client"}
    no_profile = {"tes": {"service_id": SERVICE}}
    wrong_profile = {"tes": {"profile": "tes-authzen/2", "service_id": SERVICE}}
    unknown_service = {"tes": {"profile": "tes-authzen/1", "service_id": "other-tes"}}
    odd_task_id = "task:with#odd@chars-" + "y" * 300
    others = [f"urn:geant:lifescience-ri.eu:group:vo-{i}:sub#login.aai.lifescience-ri.eu" for i in range(1023)]
    many_member = subject("kim-sub", [*others, SUBGROUP])
    many_other = subject("lou-sub", others)
    many_admin = subject("max-sub", [*others, ADMIN])
    allowed_images = with_images(*[f"ghcr.io/elixir-cloud-aai/tool-{i}:1" for i in range(1024)])
    malformed: dict[str, tuple[str, dict[str, Any]]] = {
        "create-executors-object": ("executors as an object", {**TASK, "executors": {"image": "evil.io/x"}}),
        "create-executors-string": ("executors as a string", {**TASK, "executors": "evil.io/x"}),
        "create-executors-null": ("executors null", {**TASK, "executors": None}),
        "create-executor-not-object": ("executor entry as a string", {**TASK, "executors": ["evil.io/x"]}),
        "create-executor-no-image": ("executor without image", {**TASK, "executors": [{"command": ["x"]}]}),
        "create-task-missing-executors": ("task without executors", {"name": "x"}),
    }
    T, F = True, False  # noqa: N806 (readable decision column)
    return [
        # CreateTask (cases 3, 4, 4b, 5, 5d, 6, 7, 17, plus contract checks)
        ("create-member-exact", "3", "exact group entitlement", create(BOB), T),
        (
            "create-member-subgroup",
            "4, 7",
            "subgroup matches the ':'-terminated prefix; full create "
            "projection with stripped URLs and context.tes.profile",
            create(ALICE),
            T,
        ),
        ("create-near-miss", "4b", "example-vox must not match prefix example-vo:", create(CAROL), F),
        (
            "create-parent-without-authority",
            "4b",
            "bare group URN is neither the exact value nor a subgroup",
            create(parent),
            F,
        ),
        ("create-no-claim", "5", "claims object without the entitlement claim", create(FRANK), F),
        ("create-service-client", "5d", "client-credentials subject without claims", create(SERVICE_CLIENT), F),
        ("create-string-claim", "6", "claim as a single string", create(erin), T),
        ("create-list-mixed-types", "6", "non-string list elements are ignored", create(mixed), T),
        ("create-number-claim", "6", "claim of the wrong type", create(number), F),
        ("create-admin", "3", "admin entitlement is a subgroup, so also a member", create(DAVE), T),
        (
            "create-image-denied",
            "17",
            "executor image outside the allowlist",
            create(ALICE, with_images("quay.io/evil/miner:1")),
            F,
        ),
        (
            "create-image-mixed",
            "17",
            "one allowed and one denied image",
            create(ALICE, with_images("docker.io/library/alpine:3.20", "quay.io/evil/miner:1")),
            F,
        ),
        (
            "create-image-prefix-trick",
            "17",
            "prefix must match from the start",
            create(ALICE, with_images("evil.io/docker.io/library/alpine")),
            F,
        ),
        ("create-no-executors", "17", "no executors: nothing to restrict", create(ALICE, {**TASK, "executors": []}), T),
        ("create-on-all", "7", "CreateTask only on the 'own' set", create(ALICE, set_id="all"), F),
        ("create-no-profile", "7", "context.tes.profile missing", create(ALICE, context=no_profile), F),
        ("create-wrong-profile", "7", "unknown profile version", create(ALICE, context=wrong_profile), F),
        (
            "create-unknown-service",
            "7",
            "service not configured in the policy",
            create(ALICE, context=unknown_service),
            F,
        ),
        ("create-subject-type", "7", "subject.type other than 'user'", create(bad_type), F),
        ("create-multi-issuer", "7", "issuer-qualified owner ID '<iss>|<sub>'", create(multi), T),
        ("create-long-subject", "7", "600-character subject ID", create(long), T),
        # GetTask (cases 9, 10, 11, legacy tasks)
        (
            "get-own",
            "9",
            "owner equals subject.id",
            request(ALICE, "GetTask", "tes_task", "task-a1", task_meta("alice-sub"), view),
            T,
        ),
        (
            "get-own-full",
            "9",
            "view FULL changes nothing",
            request(ALICE, "GetTask", "tes_task", "task-a1", task_meta("alice-sub"), {"view": "FULL"}),
            T,
        ),
        (
            "get-own-no-entitlement",
            "9",
            "owners read their tasks without entitlement",
            request(FRANK, "GetTask", "tes_task", "task-f1", task_meta("frank-sub"), view),
            T,
        ),
        (
            "get-other",
            "10",
            "member reads someone else's task",
            request(ALICE, "GetTask", "tes_task", "task-b1", task_meta("bob-sub"), view),
            F,
        ),
        (
            "get-other-admin",
            "9",
            "admin reads someone else's task",
            request(DAVE, "GetTask", "tes_task", "task-b1", task_meta("bob-sub"), view),
            T,
        ),
        (
            "get-missing",
            "11",
            "missing task: no properties at all",
            request(ALICE, "GetTask", "tes_task", "no-such-task", {}, view),
            F,
        ),
        (
            "get-missing-admin",
            "11",
            "missing task, admin: the PDP may allow; the TES still answers 404",
            request(DAVE, "GetTask", "tes_task", "no-such-task", {}, view),
            T,
        ),
        (
            "get-legacy-no-owner",
            "11",
            "legacy task without exact owner: only admins",
            request(ALICE, "GetTask", "tes_task", "task-legacy", task_meta(None), view),
            F,
        ),
        (
            "get-legacy-no-owner-admin",
            "11",
            "legacy task without exact owner, admin",
            request(DAVE, "GetTask", "tes_task", "task-legacy", task_meta(None), view),
            T,
        ),
        (
            "get-empty-owner",
            "11",
            "empty owner string is no owner",
            request(ALICE, "GetTask", "tes_task", "task-x", task_meta(""), view),
            F,
        ),
        (
            "get-owner-not-string",
            "11",
            "owner of the wrong type is no owner",
            request(ALICE, "GetTask", "tes_task", "task-x", {"owner": ["alice-sub"]}, view),
            F,
        ),
        (
            "get-owner-prefix",
            "10",
            "owner comparison is exact",
            request(ALICE, "GetTask", "tes_task", "task-x", task_meta("alice-sub-2"), view),
            F,
        ),
        (
            "get-multi-issuer-own",
            "9",
            "issuer-qualified owner ID",
            request(multi, "GetTask", "tes_task", "task-m1", task_meta(MULTI_ISSUER_ID), view),
            T,
        ),
        (
            "get-long-subject-own",
            "9",
            "600-character owner ID",
            request(long, "GetTask", "tes_task", "task-l1", task_meta(LONG_SUB), view),
            T,
        ),
        (
            "get-odd-task-id",
            "9",
            "task ID with ':', '#', '@' and 320 characters",
            request(ALICE, "GetTask", "tes_task", odd_task_id, task_meta("alice-sub"), view),
            T,
        ),
        (
            "get-unknown-service",
            "9",
            "own task, but service not configured",
            request(ALICE, "GetTask", "tes_task", "task-a1", task_meta("alice-sub"), view, context=unknown_service),
            F,
        ),
        (
            "get-on-task-set",
            "9",
            "GetTask on a task set is not part of the profile",
            request(ALICE, "GetTask", "tes_task_set", "own", None, view),
            F,
        ),
        # CancelTask (case 10)
        (
            "cancel-own",
            "10",
            "owner cancels",
            request(ALICE, "CancelTask", "tes_task", "task-a1", task_meta("alice-sub")),
            T,
        ),
        (
            "cancel-other",
            "10",
            "member cancels someone else's task",
            request(ALICE, "CancelTask", "tes_task", "task-b1", task_meta("bob-sub")),
            F,
        ),
        (
            "cancel-other-admin",
            "10",
            "admin cancels someone else's task",
            request(DAVE, "CancelTask", "tes_task", "task-b1", task_meta("bob-sub")),
            T,
        ),
        ("cancel-missing", "11", "missing task", request(ALICE, "CancelTask", "tes_task", "no-such-task", {}), F),
        (
            "cancel-missing-admin",
            "11",
            "missing task, admin",
            request(DAVE, "CancelTask", "tes_task", "no-such-task", {}),
            T,
        ),
        # ListTasks (cases 12, 13, 14)
        (
            "list-own-member",
            "13",
            "members list their own tasks",
            request(ALICE, "ListTasks", "tes_task_set", "own", None, view),
            T,
        ),
        (
            "list-all-member",
            "13",
            "members don't list all tasks",
            request(ALICE, "ListTasks", "tes_task_set", "all", None, view),
            F,
        ),
        (
            "list-all-admin",
            "12",
            "admins list all tasks",
            request(DAVE, "ListTasks", "tes_task_set", "all", None, view),
            T,
        ),
        (
            "list-own-admin",
            "12",
            "admin entitlement is a member subgroup",
            request(DAVE, "ListTasks", "tes_task_set", "own", None, view),
            T,
        ),
        (
            "list-own-no-claim",
            "14",
            "no entitlement: own denied",
            request(FRANK, "ListTasks", "tes_task_set", "own", None, view),
            F,
        ),
        (
            "list-all-no-claim",
            "14",
            "no entitlement: all denied",
            request(FRANK, "ListTasks", "tes_task_set", "all", None, view),
            F,
        ),
        (
            "list-own-near-miss",
            "14",
            "near-miss entitlement",
            request(CAROL, "ListTasks", "tes_task_set", "own", None, view),
            F,
        ),
        (
            "list-own-service-client",
            "5d",
            "service client without claims",
            request(SERVICE_CLIENT, "ListTasks", "tes_task_set", "own", None, view),
            F,
        ),
        (
            "list-unknown-set",
            "14",
            "set IDs other than own/all",
            request(DAVE, "ListTasks", "tes_task_set", "group:x", None, view),
            F,
        ),
        (
            "list-unknown-action",
            "14",
            "action outside the profile",
            request(DAVE, "DeleteTask", "tes_task_set", "all", None, view),
            F,
        ),
        # Realistic sizes: LS Login users carry many entitlements (review 1 of the service)
        ("create-1024-entitlements-member-last", "4", "member entitlement after 1023 others", create(many_member), T),
        ("create-1023-entitlements-non-member", "5", "1023 entitlements, none matching", create(many_other), F),
        (
            "list-all-1024-entitlements-admin",
            "12",
            "admin entitlement after 1023 others",
            request(many_admin, "ListTasks", "tes_task_set", "all", None, view),
            T,
        ),
        ("create-1024-executors-allowed", "17", "1024 executors, all images allowed", create(ALICE, allowed_images), T),
        (
            "create-1024-executors-last-denied",
            "17",
            "1023 allowed images, the last one denied",
            create(
                ALICE,
                {**allowed_images, "executors": [*allowed_images["executors"][:-1], {"image": "quay.io/evil/miner:1"}]},
            ),
            F,
        ),
        # Malformed task projections are denied when an image allowlist is set
        *[(name, "17", desc, create(ALICE, task), F) for name, (desc, task) in malformed.items()],
        (
            "create-task-missing",
            "17",
            "no task projection at all",
            request(ALICE, "CreateTask", "tes_task_set", "own", {}),
            F,
        ),
    ]


URL_CASES: list[tuple[str, str | None, str]] = [
    ("https://u:p@h/p?sig=x", "https://h/p", "spec: userinfo and query"),
    ("s3://b/k?X-Amz-Signature=x", "s3://b/k", "spec: presigned query"),
    ("drs://u:p@h/obj", "drs://h/obj", "spec: userinfo, non-HTTP scheme"),
    ("ftp://a@b@h/p", "ftp://h/p", "spec: last '@' in the authority"),
    ("https://h?sig=x", "https://h", "spec: query right after the host"),
    ("https://h/p#frag", "https://h/p", "spec: fragment cut"),
    ("s3://b/user@x/f", "s3://b/user@x/f", "spec: '@' in the path is kept"),
    ("file:///d/f", "file:///d/f", "spec: empty authority unchanged"),
    ("https://u:p?ss@h/p", None, "spec step 2: '?' in userinfo"),
    ("https://evil?x=@trusted/p", None, "spec step 2: '@' in the query"),
    ("u:p@host/x://y", None, "spec: '://' not after a scheme, '@'"),
    ("1s://u@h/p", None, "spec: invalid scheme, '@'"),
    ("/local/path", "/local/path", "spec: no scheme, no '@' or '?'"),
    ("/local/path?x", None, "spec: no scheme with '?' is omitted"),
    ("user@host:path", None, "spec: no scheme with '@' is omitted"),
    ("https://u@h", "https://h", "authority to the end"),
    ("drs://u:p@h/obj#frag", "drs://h/obj", "userinfo and fragment"),
    ("http://[::1]:8080/p?x=1", "http://[::1]:8080/p", "IPv6 host and port kept"),
    ("gs://b/k#x?y", "gs://b/k", "first of '?' or '#'"),
    ("https://h#a@b", None, "step 2: '@' after '#' before any '/'"),
    ("https://u@h?q", "https://h", "userinfo before a query after the host"),
    ("relative?x=@", None, "no scheme with '?' and '@'"),
    ("HTTPS://H/%41", "HTTPS://H/%41", "no normalisation"),
    ("git+ssh://u@h/r", "git+ssh://h/r", "scheme with '+'"),
    (
        "https://evil.example\\@trusted.example/p?x=1",
        None,
        "spec step 2b: backslash before the first '/' (WHATWG: '/')",
    ),
    ("https://u:p@h\\x@y/p", None, "spec step 2b: backslash in userinfo"),
    ("https://h/a\\b@c", "https://h/a\\b@c", "backslash after the first '/' kept"),
    ("/local/file#1", "/local/file#1", "spec step 5: no scheme, no '@' or '?': fragment kept"),
]


SUBMITTED_TASK: dict[str, Any] = {
    "id": "client-chosen-id",
    "state": "COMPLETE",
    "name": "hello",
    "tags": {"project": "demo"},
    "resources": {
        "cpu_cores": 1,
        "ram_gb": 1.0,
        "disk_gb": 5.0,
        "preemptible": False,
        "zones": [],
        "backend_parameters": {"secret": "do-not-send"},
    },
    "volumes": ["/vol/a"],
    "executors": [
        {"image": "docker.io/library/alpine:3.20", "command": ["echo", "secret"], "env": {"TOKEN": "do-not-send"}}
    ],
    "inputs": [
        {"url": "s3://bucket/in.txt?X-Amz-Signature=do-not-send", "path": "/data/in.txt", "type": "FILE"},
        {"content": "do-not-send", "path": "/data/inline.txt", "type": "FILE"},
    ],
    "outputs": [{"url": "https://user:do-not-send@storage.example.org/out/", "path": "/data/out", "type": "DIRECTORY"}],
}
"""Task a hook test submits for golden case 7 (with secrets that must not reach the PDP)."""


def hook_create() -> dict[str, Any]:
    """Render the hook-side golden request for case 7.

    Placeholders ``{{subject_id}}``, ``{{iss}}``, ``{{sub}}`` and
    ``{{client_id}}`` stand for per-TES fixture values.

    Returns:
        The golden file content.
    """
    task = {
        **TASK,
        "inputs": [
            {"url": "s3://bucket/in.txt", "path": "/data/in.txt", "type": "FILE"},
            {"path": "/data/inline.txt", "type": "FILE"},
        ],
    }
    req = request(
        {
            "type": "user",
            "id": "{{subject_id}}",
            "properties": {
                "iss": "{{iss}}",
                "sub": "{{sub}}",
                "client_id": "{{client_id}}",
                "scope": ["openid", "eduperson_entitlement"],
                "claims": {"eduperson_entitlement": [SUBGROUP]},
            },
        },
        "CreateTask",
        "tes_task_set",
        "own",
        {"task": task},
        aprops={},
    )
    return {
        "name": "hook-create",
        "case": "7",
        "description": "CreateTask as the PDP must see it: stripped URLs, no backend_parameters, "
        "command, env or content; allowlist [eduperson_entitlement]",
        "submit": SUBMITTED_TASK,
        "request": req,
    }


def render() -> dict[Path, str]:
    """Render all golden files.

    Returns:
        A map from path to file content.
    """
    files: dict[Path, str] = {OUT / "hook" / "create.json": json.dumps(hook_create(), indent=2, sort_keys=True) + "\n"}
    for name, case, description, req, decision in cases():
        body = {
            "name": name,
            "case": case,
            "description": description,
            "request": req,
            "expect": {"reference_policy": {"decision": decision}},
        }
        files[OUT / "requests" / f"{name}.json"] = json.dumps(body, indent=2, sort_keys=True) + "\n"
    urls = [
        {"input": raw, "expected": expected, "description": description} for raw, expected, description in URL_CASES
    ]
    files[OUT / "url-stripping.json"] = json.dumps(urls, indent=2) + "\n"
    return files


def main() -> int:
    """Write or check the golden files.

    Returns:
        The exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="only compare with the committed files")
    args = parser.parse_args()
    files = render()
    existing = set((OUT / "requests").glob("*.json")) if (OUT / "requests").exists() else set()
    if args.check:
        stale = [p for p, text in files.items() if not p.exists() or p.read_text() != text]
        stale += sorted(existing - set(files))
        for path in stale:
            print(f"out of date: {path.relative_to(ROOT)}")
        return 1 if stale else 0
    for path in existing - set(files):
        path.unlink()
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    print(f"wrote {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())

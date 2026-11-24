"""Generate the phase-1 golden AuthZEN requests and URL stripping cases.

Until the Poiesis hook writes golden requests from its own tests
(``golden/<tes>/``), these files stand in for them: one file per
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
PROFILE = "tes-authzen/3"
"""The current profile version (spec section 13), sent by the hook-side golden request."""


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


def with_v2_properties(subj: dict[str, Any], **properties: Any) -> dict[str, Any]:
    """Add ``tes-authzen/2`` subject properties (spec section 12).

    A ``key_age`` also sets ``snapshot_age`` to the same value, as Poiesis
    sends both for API keys.

    Args:
        subj: The subject.
        **properties: The properties to add (``via``, ``credential_id``,
            ``actor``, ``key_age``).

    Returns:
        A copy of the subject with the properties added.
    """
    props = {**subj["properties"], **properties}
    if "key_age" in properties:
        props["snapshot_age"] = properties["key_age"]
    return {**subj, "properties": props}


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
    wrong_profile = {"tes": {"profile": "tes-authzen/4", "service_id": SERVICE}}
    v2 = {"tes": {"profile": "tes-authzen/2", "service_id": SERVICE}}
    v3 = {"tes": {"profile": PROFILE, "service_id": SERVICE}}
    alice_v2 = with_v2_properties(ALICE, via="oidc")
    dave_v2 = with_v2_properties(DAVE, via="oidc")
    alice_key = with_v2_properties(ALICE, via="apikey", credential_id="key-a1", key_age=3600)
    alice_delegated = with_v2_properties(ALICE, via="oidc", actor={"iss": ISS, "sub": "proxy-client"})
    dave_delegated = with_v2_properties(DAVE, via="oidc", actor={"iss": ISS, "sub": "proxy-client"})
    dave_actor_null = with_v2_properties(DAVE, via="oidc", actor=None)
    v1 = {"tes": {"profile": "tes-authzen/1", "service_id": SERVICE}}
    shared = {**task_meta("bob-sub"), "groups": ["lab-alpha"]}
    own_shared = {**task_meta("alice-sub"), "groups": ["lab-alpha"]}
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
        (
            "create-admin",
            "3",
            "the tes-admins entitlement is a member subgroup: member powers, nothing more",
            create(DAVE),
            T,
        ),
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
            "create-profile-2",
            "7",
            "profile tes-authzen/2 with the subject property via",
            create(alice_v2, context=v2),
            T,
        ),
        (
            "create-profile-2-apikey",
            "7",
            "profile tes-authzen/2, API key subject with credential_id, key_age and snapshot_age",
            create(alice_key, context=v2),
            T,
        ),
        (
            "create-profile-2-actor",
            "7",
            "profile tes-authzen/2, delegated token: members keep member powers",
            create(alice_delegated, context=v2),
            T,
        ),
        (
            "create-profile-2-actor-admin",
            "7",
            "profile tes-authzen/2, delegated token of a tes-admins member: may create as a member",
            create(dave_delegated, context=v2),
            T,
        ),
        (
            "create-profile-2-near-miss",
            "4b",
            "profile tes-authzen/2 changes nothing for a near-miss entitlement",
            create(with_v2_properties(CAROL, via="oidc"), context=v2),
            F,
        ),
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
            "owners keep their tasks after the entitlement is revoked",
            request(FRANK, "GetTask", "tes_task", "task-f1", task_meta("frank-sub"), view),
            T,
        ),
        (
            "get-own-near-miss",
            "9",
            "owner with only a near-miss entitlement: still the owner",
            request(CAROL, "GetTask", "tes_task", "task-c1", task_meta("carol-sub"), view),
            T,
        ),
        (
            "get-other-no-entitlement",
            "10",
            "no entitlement, someone else's task",
            request(FRANK, "GetTask", "tes_task", "task-b1", task_meta("bob-sub"), view),
            F,
        ),
        (
            "get-own-admin",
            "9",
            "a tes-admins member reads their own task",
            request(DAVE, "GetTask", "tes_task", "task-d1", task_meta("dave-sub"), view),
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
            "an admin entitlement gives no access to someone else's task (owner only)",
            request(DAVE, "GetTask", "tes_task", "task-b1", task_meta("bob-sub"), view),
            F,
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
            "missing task, admin entitlement: denied (owner only)",
            request(DAVE, "GetTask", "tes_task", "no-such-task", {}, view),
            F,
        ),
        (
            "get-legacy-no-owner",
            "11",
            "legacy task without exact owner: reachable by nobody",
            request(ALICE, "GetTask", "tes_task", "task-legacy", task_meta(None), view),
            F,
        ),
        (
            "get-legacy-no-owner-admin",
            "11",
            "legacy task without exact owner, admin entitlement: denied (owner only)",
            request(DAVE, "GetTask", "tes_task", "task-legacy", task_meta(None), view),
            F,
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
        (
            "get-own-profile-2-groups",
            "9",
            "profile tes-authzen/2, own task with groups",
            request(alice_v2, "GetTask", "tes_task", "task-a1", own_shared, view, context=v2),
            T,
        ),
        (
            "get-other-profile-2-groups",
            "10",
            "profile tes-authzen/2, someone else's task with groups: the reference policy ignores groups",
            request(alice_v2, "GetTask", "tes_task", "task-b1", shared, view, context=v2),
            F,
        ),
        (
            "get-other-admin-profile-2",
            "9",
            "profile tes-authzen/2, admin entitlement on someone else's task: denied (owner only)",
            request(dave_v2, "GetTask", "tes_task", "task-b1", shared, view, context=v2),
            F,
        ),
        (
            "get-other-admin-actor",
            "10",
            "profile tes-authzen/2, delegated token of an admin-entitled user: someone else's task denied",
            request(dave_delegated, "GetTask", "tes_task", "task-b1", shared, view, context=v2),
            F,
        ),
        (
            "get-other-admin-actor-null",
            "10",
            "delegated token (actor null) of an admin-entitled user: someone else's task denied",
            request(dave_actor_null, "GetTask", "tes_task", "task-b1", shared, view, context=v2),
            F,
        ),
        (
            "get-other-admin-actor-profile-1",
            "10",
            "tes-authzen/1 with an actor, admin entitlement: someone else's task denied",
            request(dave_delegated, "GetTask", "tes_task", "task-b1", task_meta("bob-sub"), view, context=v1),
            F,
        ),
        (
            "get-legacy-admin-actor",
            "11",
            "legacy task without exact owner, delegated token of an admin: denied",
            request(dave_delegated, "GetTask", "tes_task", "task-legacy", task_meta(None), view, context=v2),
            F,
        ),
        (
            "get-own-admin-actor",
            "9",
            "profile tes-authzen/2, delegated token of a tes-admins member: own task as a member",
            request(dave_delegated, "GetTask", "tes_task", "task-d1", task_meta("dave-sub"), view, context=v2),
            T,
        ),
        (
            "cancel-other-admin-actor",
            "10",
            "profile tes-authzen/2, delegated token of an admin-entitled user cancels someone else's task",
            request(dave_delegated, "CancelTask", "tes_task", "task-b1", shared, context=v2),
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
            "cancel-own-no-entitlement",
            "10",
            "owners cancel their tasks after the entitlement is revoked",
            request(FRANK, "CancelTask", "tes_task", "task-f1", task_meta("frank-sub")),
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
            "an admin entitlement can't cancel someone else's task (owner only)",
            request(DAVE, "CancelTask", "tes_task", "task-b1", task_meta("bob-sub")),
            F,
        ),
        ("cancel-missing", "11", "missing task", request(ALICE, "CancelTask", "tes_task", "no-such-task", {}), F),
        (
            "cancel-missing-admin",
            "11",
            "missing task, admin entitlement: denied (owner only)",
            request(DAVE, "CancelTask", "tes_task", "no-such-task", {}),
            F,
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
            "an admin entitlement doesn't list all tasks: 'all' is never allowed",
            request(DAVE, "ListTasks", "tes_task_set", "all", None, view),
            F,
        ),
        (
            "list-own-admin",
            "12",
            "the tes-admins entitlement is a member subgroup: lists own tasks",
            request(DAVE, "ListTasks", "tes_task_set", "own", None, view),
            T,
        ),
        (
            "list-own-no-claim",
            "14",
            "no entitlement: own tasks still listed (only CreateTask needs it)",
            request(FRANK, "ListTasks", "tes_task_set", "own", None, view),
            T,
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
            "near-miss entitlement: own tasks still listed",
            request(CAROL, "ListTasks", "tes_task_set", "own", None, view),
            T,
        ),
        (
            "list-own-service-client",
            "5d",
            "service client without claims lists its own tasks",
            request(SERVICE_CLIENT, "ListTasks", "tes_task_set", "own", None, view),
            T,
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
        (
            "list-own-profile-2",
            "13",
            "profile tes-authzen/2, members list their own tasks",
            request(alice_v2, "ListTasks", "tes_task_set", "own", None, view, context=v2),
            T,
        ),
        (
            "list-all-admin-profile-2",
            "12",
            "profile tes-authzen/2, admin entitlement: 'all' is never allowed",
            request(dave_v2, "ListTasks", "tes_task_set", "all", None, view, context=v2),
            F,
        ),
        (
            "list-all-admin-actor",
            "13",
            "profile tes-authzen/2, delegated token of an admin-entitled user: all denied",
            request(dave_delegated, "ListTasks", "tes_task_set", "all", None, view, context=v2),
            F,
        ),
        (
            "list-own-admin-actor",
            "13",
            "profile tes-authzen/2, delegated token of a tes-admins member lists own tasks as a member",
            request(dave_delegated, "ListTasks", "tes_task_set", "own", None, view, context=v2),
            T,
        ),
        # Profile tes-authzen/3 (spec section 13): tes_task_set:all is no longer in the vocabulary
        ("create-profile-3", "7", "profile tes-authzen/3, member creates", create(ALICE, context=v3), T),
        (
            "create-on-all-profile-3",
            "7",
            "profile tes-authzen/3, CreateTask on 'all'",
            create(ALICE, set_id="all", context=v3),
            F,
        ),
        (
            "get-own-profile-3",
            "9",
            "profile tes-authzen/3, owner reads",
            request(ALICE, "GetTask", "tes_task", "task-a1", task_meta("alice-sub"), view, context=v3),
            T,
        ),
        (
            "get-other-admin-profile-3",
            "9",
            "profile tes-authzen/3, admin entitlement on someone else's task: denied",
            request(DAVE, "GetTask", "tes_task", "task-b1", task_meta("bob-sub"), view, context=v3),
            F,
        ),
        (
            "get-legacy-no-owner-admin-profile-3",
            "11",
            "profile tes-authzen/3, task without owner, admin entitlement: denied",
            request(DAVE, "GetTask", "tes_task", "task-legacy", task_meta(None), view, context=v3),
            F,
        ),
        (
            "cancel-own-profile-3",
            "10",
            "profile tes-authzen/3, owner cancels",
            request(ALICE, "CancelTask", "tes_task", "task-a1", task_meta("alice-sub"), context=v3),
            T,
        ),
        (
            "cancel-other-admin-profile-3",
            "10",
            "profile tes-authzen/3, admin entitlement cancels someone else's task: denied",
            request(DAVE, "CancelTask", "tes_task", "task-b1", task_meta("bob-sub"), context=v3),
            F,
        ),
        (
            "list-own-profile-3",
            "13",
            "profile tes-authzen/3, members list their own tasks",
            request(ALICE, "ListTasks", "tes_task_set", "own", None, view, context=v3),
            T,
        ),
        (
            "list-all-member-profile-3",
            "14",
            "profile tes-authzen/3, 'all' is not in the vocabulary",
            request(ALICE, "ListTasks", "tes_task_set", "all", None, view, context=v3),
            F,
        ),
        (
            "list-all-admin-profile-3",
            "14",
            "profile tes-authzen/3, 'all' is not in the vocabulary, also with an admin entitlement",
            request(DAVE, "ListTasks", "tes_task_set", "all", None, view, context=v3),
            F,
        ),
        # Poiesis's own resource type in profile tes-authzen/2: not TES, always denied
        (
            "api-keys-get-task-admin",
            "7",
            "GetTask on poiesis_api_keys, admin: the resource type alone is outside the TES vocabulary",
            request(dave_v2, "GetTask", "poiesis_api_keys", "bob-sub", {"owner": "bob-sub"}, view, context=v2),
            F,
        ),
        (
            "api-keys-revoke-admin",
            "7",
            "Poiesis RevokeApiKeys on poiesis_api_keys, admin: outside the TES vocabulary",
            request(dave_v2, "RevokeApiKeys", "poiesis_api_keys", "bob-sub", None, context=v2),
            F,
        ),
        (
            "api-keys-list-admin",
            "7",
            "Poiesis ListApiKeys on poiesis_api_keys, admin: outside the TES vocabulary",
            request(dave_v2, "ListApiKeys", "poiesis_api_keys", "bob-sub", None, context=v2),
            F,
        ),
        (
            "api-keys-list-own",
            "7",
            "Poiesis ListApiKeys with ?owner= the caller's own owner: outside the TES vocabulary",
            request(alice_v2, "ListApiKeys", "poiesis_api_keys", "alice-sub", None, context=v2),
            F,
        ),
        # Realistic sizes: LS Login users carry many entitlements (review 1 of the service)
        ("create-1024-entitlements-member-last", "4", "member entitlement after 1023 others", create(many_member), T),
        ("create-1023-entitlements-non-member", "5", "1023 entitlements, none matching", create(many_other), F),
        (
            "list-all-1024-entitlements-admin",
            "12",
            "admin entitlement after 1023 others: 'all' is never allowed",
            request(many_admin, "ListTasks", "tes_task_set", "all", None, view),
            F,
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
    ("https:///u:p@h/p", None, "spec step 4b: empty authority, '@' in the rest"),
    ("file:///d/user@x/f", None, "spec step 4b: accepted over-omission"),
    ("file:///d/f?x=@y", "file:///d/f", "spec step 4b: '@' only in the query"),
    ("https://\t/u:p@h/p", None, "spec step 0: TAB (WHATWG deletes it)"),
    ("https://u:p@h\n/p", None, "spec step 0: LF"),
    ("/local/a\r\nb", None, "spec step 0: CR LF without a scheme"),
    ("https://x@/u:p@h/p", None, "spec step 4b: host empty after dropping userinfo"),
    ("https://@/u:p@h/p", None, "spec step 4b: empty userinfo, empty host"),
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
                "scope": "{{scope}}",
                "claims": {"eduperson_entitlement": [SUBGROUP]},
            },
        },
        "CreateTask",
        "tes_task_set",
        "own",
        {"task": task},
        aprops={},
        context={"tes": {"profile": PROFILE, "service_id": SERVICE}},
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

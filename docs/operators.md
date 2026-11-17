# Operators

These notes are for operators who run the reference decision services.

## Deployment

This compose file is a local test and reference setup. All containers are read-only, drop all capabilities and run without new privileges, and ports bind to loopback only. But OPA's and OpenFGA's own APIs (18181, 18080) are published for the findings tests and are **not authenticated**: any local process can change policy data or tuples. A deployment publishes only the shims and enables OPA token authorization and OpenFGA preshared keys.

## Reference policy

The policy implements spec [§7](specification.md#7-reference-decision-service-and-engines) with LS Login entitlements:

| Action | Resource | Allowed if |
|---|---|---|
| `CreateTask` | `tes_task_set:own` | the caller is a member (exact group, or a subgroup via the `…:example-vo:` prefix) and every executor image starts with an allowed prefix (an empty prefix list allows any image) |
| `GetTask`, `CancelTask` | `tes_task:<id>` | the caller is a member and `resource.properties.owner == subject.id` (owner present and not empty), or the caller is an admin; a missing or legacy owner: admins only. Owners need a current entitlement: revoking it ends their access at once (spec Q11, option b) |
| `ListTasks` | `tes_task_set:own` | the caller is a member |
| `ListTasks` | `tes_task_set:all` | the caller is an admin |

Anything else is denied, and so is any request with another profile or an unknown `service_id`.

## OpenFGA mapping (shim)

| AuthZEN in | OpenFGA out |
|---|---|
| `subject` | `user:h-<sha256(subject.id)>`, properties `id` = the real ID, and `entitlements` (list) from the policy's `entitlement_claim` |
| `tes_task:<id>` | `tes_service:<service>`, properties `owner` (`""` when absent) and `images` (`[""]` when the task projection or its executor list is missing or malformed, so an allowlist denies) |
| `tes_task_set:<own\|all>` | `tes_task_set:<service>/<own\|all>`, same properties |
| `action.name` | the relation of the same name |

OpenFGA turns properties into the condition parameters `subject_id`, `subject_entitlements`, `resource_owner` and `resource_images`. The shim always sends all four (review 2, finding 3). Ownership is the condition `is_owner` on a `user:*` tuple. Membership and admin rights are the condition `entitled` on `user:*` tuples, whose tuple context holds the allowed values and prefixes from the data file. On `tes_service`, `GetTask` and `CancelTask` are `(owner and member) or admin`, with a `member` relation carrying the members' `entitled` tuple.

The shim scopes task sets per service (`<service>/own`). That way an unknown `service_id` is denied by both engines alike. Spec [§7](specification.md#7-reference-decision-service-and-engines) only names the `tes_service` rewrite for tasks, so this is a small addition.

## Owner rule

Owner rule (Q11, decided option b): owners read and cancel their own tasks only while they hold a member entitlement, so in a PDP-only deployment revoking the entitlement ends access at once, as the claim rule does when it is set. An operator who wants owners to keep access after leaving the group drops `member` from the owner branch in their copy of the policy (OPA: `owner_or_admin`; OpenFGA: `owner and member`). Golden cases `get-own-no-entitlement`, `get-own-near-miss`, `cancel-own-no-entitlement`, `get-other-no-entitlement` and `get-own-admin`. Because `is_owner` now sits inside `owner and member`, a request from a non-member that lacks `resource_owner` or `subject_id` may get a plain deny from OpenFGA instead of the 400 of finding F1; it is never an allow, and the shim always sends both parameters, so the shim, not OpenFGA, guarantees them.

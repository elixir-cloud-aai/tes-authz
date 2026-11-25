# Operators

These notes are for operators who run the reference decision services.

## Deployment

`compose.yaml` is a local test and reference setup (`make up`). All containers are read-only, drop all capabilities and run without new privileges, and ports bind to loopback only. But OPA's and OpenFGA's own APIs (18181, 18080) are published for the findings tests and are **not authenticated**: any local process can change policy data or tuples. A deployment publishes only the shims and enables OPA token authorization and OpenFGA preshared keys, or keeps the engines' APIs off the network, as the Kubernetes manifest below does for OPA.

## Kubernetes

[`deploy/kubernetes/tes-authz.yaml`](https://github.com/elixir-cloud-aai/tes-authz/blob/dev/deploy/kubernetes/tes-authz.yaml) runs the OPA decision service in one pod: OPA with the reference policy, behind the AuthZEN front `shims/opa_front.py`. There is no image of its own: the pod uses the OPA and Python images of `compose.yaml` (pinned by digest), and the policy, the policy data and the front's code come from ConfigMaps. So a deployment is pinned by a commit of this repository, without a release.

| Object | What |
|---|---|
| Deployment `tes-authz` | container `opa` (Data API on the pod's loopback `127.0.0.1:8181` only, so it is never reachable from other pods; `/health` on the diagnostic port 8282 for the probes) and container `opa-front` (AuthZEN on port 8080) |
| Service `tes-authz` | `ClusterIP`, port 8080 only: the evaluation URL is `http://tes-authz.<namespace>.svc:8080/access/v1/evaluation` |
| NetworkPolicy `tes-authz` | only pods labelled `tes-authz/client: "true"` reach the front; label the TES API pods (Poiesis: `api.podLabels`) |

The NetworkPolicy needs a network plugin that enforces NetworkPolicies (most do, e.g. OVN-Kubernetes on OpenShift, Calico, Cilium, kindnet); without one, every pod reaches the front. Labels are no identity: whoever may create or label pods in the namespace can pose as a client, or give a pod the Service's labels and answer decisions in its place. Allow only the operator and the TES (whose task pods get labels the TES sets, not the user) to create pods there, or authenticate TES-to-service traffic with mesh mTLS.

NetworkPolicies add up: if another policy in the namespace admits all pods of the namespace (OpenShift projects often have one, e.g. `deny-other-namespaces-access` with `podSelector: {}`), every pod there, task pods included, reaches the front and OPA's diagnostic port (`/health`, `/metrics`). They still don't reach OPA's Data API, and no task data passes through the service, but they can probe the policy with made-up claims and load the single front, whose overload means `503` for every TES user. To keep them out, run the decision service in a namespace of its own: add a `namespaceSelector` (`kubernetes.io/metadata.name: <TES namespace>`) next to the `podSelector` in the NetworkPolicy's `from` entry, use the Service's name in that namespace in the TES configuration and in the front's `SHIM_BASE_URL` (the URL that `/.well-known/authzen-configuration` advertises) (and in Poiesis's `extraEgress` below, with the same `namespaceSelector`).

The pod has no service account token, runs as a non-root user with a read-only root file system, without capabilities and with the runtime's default seccomp profile. It needs no Secret: the front takes no credential, and only labelled pods reach it. The connection is plain HTTP inside the cluster, which TES implementations warn about (spec [§4](specification.md#4-failure-semantics-configuration-security)); use a service mesh with mTLS where the cluster network isn't trusted.

Deploy from a checkout at the commit you want to run, into the namespace of the TES:

```sh
commit=<full commit SHA>
namespace=<namespace of the TES>
git clone https://github.com/elixir-cloud-aai/tes-authz.git
git -C tes-authz checkout --detach "$commit"
# The policy data: a copy of the reference data with your groups (below)
cp tes-authz/config/reference-policy.json policy-data.json
"${EDITOR:-vi}" policy-data.json
kubectl -n "$namespace" create configmap tes-authz-policy \
  --from-file=tes-authz/engines/opa/policy/tes_authz.rego
kubectl -n "$namespace" create configmap tes-authz-shims \
  --from-file=tes-authz/shims/common.py --from-file=tes-authz/shims/opa_front.py
kubectl -n "$namespace" create configmap tes-authz-data --from-file=data.json=policy-data.json
kubectl -n "$namespace" apply -f tes-authz/deploy/kubernetes/tes-authz.yaml
kubectl -n "$namespace" rollout status deployment/tes-authz
```

OPA and the front read their files at startup only. To change the policy data later, replace the ConfigMap and restart the pod (the Deployment's `Recreate` strategy stops the old pod first, so no caller gets decisions of the old data afterwards; the TES answers `503` for the few seconds in between). Run one deployment at a time per namespace: the ConfigMaps are updated one by one. A ConfigMap holds at most 1 MiB, which group lists and image prefixes don't come near; for larger data, use OPA bundles instead.

```sh
kubectl -n "$namespace" create configmap tes-authz-data --from-file=data.json=policy-data.json \
  --dry-run=client -o yaml | kubectl -n "$namespace" apply -f -
kubectl -n "$namespace" rollout restart deployment/tes-authz
```

The policy data (`data.json`) has the fields of `config/reference-policy.json`:

- `entitlement_claim`: the claim in `subject.properties.claims` with the caller's groups. The TES must send it: in Poiesis, `authz.decisionService.claims: [eduperson_entitlement]`.
- `members`: exact `values` and raw string `prefixes` of the entitlement that may create tasks (e.g. one compute group). It is needed for `CreateTask` only: everyone reads, lists and cancels their own tasks, also after the entitlement is revoked, and nobody reaches other owners' tasks. There is no admin group: a data file that still has `admins` makes OPA deny every request and the OpenFGA setup job refuse to start (see the upgrade notes below).
- `service_clients` (optional): the service clients that may create tasks without the entitlement, as a list of `{"iss": "<issuer>", "client_id": "<client ID>"}`, e.g. proTES's LS Login client. Leave it out, or make it `[]`, for none. Both values are compared exactly (`https://login.aai.lifescience-ri.eu/oidc/` and `https://login.aai.lifescience-ri.eu/oidc` are different issuers) and must be non-empty strings without spaces or control characters, with no other keys in an entry; otherwise OPA denies every request and the OpenFGA setup job refuses to start (`malformed 'service_clients'`). See [Service clients](#service-clients) below.
- `image_prefixes`: allowed executor image prefixes, compared as raw strings (`alpine:3` doesn't start with `docker.io/library/`); an empty list allows any image, but leaving the field out denies every creation.
- `services`: the service-info IDs of the TES implementations the policy answers for (Poiesis: `org.ga4gh.poiesis`); requests from any other service are denied.

Then point the TES at the Service, e.g. for Poiesis (Helm values):

```yaml
api:
  podLabels:
    tes-authz/client: "true"
authz:
  decisionService:
    url: http://tes-authz.<namespace>.svc:8080/access/v1/evaluation
    claims: [eduperson_entitlement]
```

With Poiesis's own NetworkPolicy on (`networkPolicy.enabled: true`), the API pods may send only DNS and HTTPS; allow the decision service too, or every TES call answers `503`:

```yaml
networkPolicy:
  extraEgress:
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: tes-authz
      ports:
        - port: 8080
          protocol: TCP
```

To move to another commit of this repository, check it out and run the `create configmap` commands again with `--dry-run=client -o yaml | kubectl -n "$namespace" apply -f -`, apply the manifest, and restart the pod as above.

**OpenShift** assigns the user and the seccomp profile itself, and its default security context constraint refuses pods that set a fixed user. Remove the three fields before applying, e.g. with [yq](https://github.com/mikefarah/yq):

```sh
yq 'del(.spec.template.spec.securityContext.runAsUser, .spec.template.spec.securityContext.runAsGroup, .spec.template.spec.securityContext.seccompProfile)' \
  tes-authz/deploy/kubernetes/tes-authz.yaml | kubectl -n "$namespace" apply -f -
```

`make kubernetes` (`scripts/test-kubernetes.sh`) deploys the manifest with the reference policy data to the current `kubectl` context (e.g. a kind cluster), replays the golden requests through a port forward, and checks from client pods that only labelled pods reach the Service and that no pod reaches OPA on the pod IP. CI runs it on kind.

## Reference policy

The policy implements spec [§7](specification.md#7-reference-decision-service-and-engines) with LS Login entitlements. It is owner only, like a TES's default (spec [§3](specification.md#3-the-contract-authzen-mapping)): by default a TES asks the decision service only whether the caller may create a task, and decides reading, listing and cancelling itself (the caller's own tasks only). Operators can switch those operations on in the TES (`authz.operations`, below); the decision service then decides them alone, and with this policy the results stay the same.

| Action | Resource | Allowed if |
|---|---|---|
| `CreateTask` | `tes_task_set:own` | under `tes-authzen/3`, `resource.properties.owner` is the caller; the caller is a member (exact group, or a subgroup via the `…:example-vo:` prefix) or a listed service client (below); and every executor image starts with an allowed prefix (an empty prefix list allows any image) |
| `GetTask`, `CancelTask` | `tes_task:<id>` | `resource.properties.owner == subject.id` (owner present and not empty), with or without a current entitlement; a task without an owner: nobody |
| `ListTasks` | `tes_task_set:own` | always, as a plain allow: the list scope `own` (the TES lists only the caller's tasks); never the scope `all` |
| `ListTasks` | `tes_task_set:all` | never (profile `tes-authzen/3` doesn't have it) |

There are no admins: no entitlement reads, lists or cancels another owner's tasks. Operators inspect and clean up tasks through the infrastructure (the TES's database or cluster), and sharing belongs in clients. A delegated token (an `actor` in `subject.properties`) has its subject's powers.

Anything else is denied, and so is any request with a profile other than `tes-authzen/1`, `/2` and `/3`, or an unknown `service_id`.

The TES's built-in claim rule (`authz.requiredClaim.*`), if set, gates `CreateTask` only (spec §5), so it doesn't take owners' tasks away either.

Poiesis sends `tes-authzen/2` (spec [§12](specification.md#12-tes-authzen2-delta-to-1)). The reference policy decides it like `/1` and `/3` and ignores the additions, with these consequences for Poiesis (checked against Poiesis 0fa56aa; see its [authorization docs](https://github.com/JaeAeich/poiesis/blob/milestone/docs/app/docs/concepts/authorization.md)):

- **Sharing and admin read** (`authz.sharing`, `authz.adminRead`) are Poiesis extensions outside the contract (spec §12), off by default. Keep them off: a deployment that turns them on no longer meets the owner-only rule, and the policy denies what they would ask anyway (`ListTasks` on `all`, other owners' tasks).
- **Delegated tokens** (`subject.properties.actor`) have their subject's powers. The policy doesn't look at who the actor is: if your issuers mint delegated tokens (RFC 8693 token exchange) for actors you don't trust with their subjects' powers, deny them in your policy.
- **API keys** (`via: apikey`) carry the claims snapshot taken when the key was minted, and the policy ignores `key_age` and `snapshot_age`. Revoking an entitlement therefore stops `CreateTask` with that user's keys only when they expire (Poiesis `auth.apiKeys.maxTtl`). Shorten the key lifetime, or refuse old snapshots in your policy.
- **API keys of other owners**: the policy denies `RevokeApiKeys` and `ListApiKeys` on `poiesis_api_keys`, so admins can't list or revoke other owners' keys while Poiesis uses it. Callers still list and revoke their own keys, as long as they don't pass `?owner=` (with it, even for their own owner, Poiesis asks and is denied).
- **Responses**: the policy never answers with a `context.tes`.

### Service clients

Service clients (client-credentials tokens, e.g. proTES in front of a TES) carry no entitlements. Their create grant belongs in the policy data, not in the TES (spec [§5](specification.md#5-built-in-claim-rule-and-composition)): list them in `service_clients`, and in the TES only for authentication (which issuers and client IDs it accepts, and with which audience). A deployment that renders both from one list, as a TES chart can, keeps them in step.

A listed client may create tasks when the request's `subject.properties.iss` and `client_id` equal a listed pair and `subject.properties.sub` equals `client_id`. LS Login client-credentials tokens have `sub` = `client_id` = the client ID. A user who signs in through that client gets a token with the same `client_id` but their own `sub`, so the service-client grant doesn't apply to them; they need the entitlement like everyone else. The image allowlist and, under `tes-authzen/3`, the owner check apply as for members.

Like any creator, a listed client then owns its tasks: it reads, lists and cancels them by the owner rule, and nothing else (no other owner's tasks, no list scope `all`, no admin). Behind proTES, that means proTES owns every task it forwards, and proTES decides which of its users sees which task. Unlisted client-credentials tokens are denied `CreateTask`, as before. A delegated token whose subject is a listed client has the client's powers, like any delegated token; which actors a TES accepts is the TES's setting.

```json
"service_clients": [
  {"iss": "https://login.aai.lifescience-ri.eu/oidc/", "client_id": "<proTES client ID>"}
]
```

The TES must send `iss`, `sub` and `client_id` in `subject.properties` for client tokens (spec [§3.1](specification.md#31-subject)). It should also refuse a user token whose `sub` equals a listed client ID at the same issuer, so that no user can pose as a client or share its tasks. Golden cases `*-listed-client*`, `create-unlisted-client` and `create-service-client` (spec case 31).

To change any of this, extend the policy. A policy that grants more than owner access (another owner's task, the list scope `all`) takes effect only for the operations a TES switches on.

### TES configuration for the decision service

These settings are on the TES side (spec [§4.2](specification.md#42-configuration-keys)); names are the generic ones, each TES maps them (TESK: `tesk.api.authz.operations`, `tesk.api.authz.failure.<operation>`).

| Setting | Default | Meaning |
|---|---|---|
| `authz.operations` | `[create]` | operations the decision service decides: `create` (always), `get`, `list`, `cancel`. Operations not listed are owner only, decided by the TES without a call. |
| `authz.failure.<operation>` | `closed` | what a failed decision (timeout, error, malformed answer) means for that operation: `closed` answers `503`; `open` falls back to the owner rule (own tasks only, never allow-all). `create` must stay `closed`. The meaning of `open` is still a proposal (spec Q12). |

With the default, a decision-service outage stops only task creation (`503`); callers keep reading, listing and cancelling their own tasks. Switch `get`, `list` or `cancel` on only for a policy that decides more than the owner rule (e.g. sharing, or ending access with the entitlement); with this reference policy, switching them on adds calls and makes the operations depend on the decision service, but changes no result.

A switched-on `ListTasks` asks once per page. The answer's list scope decides what the TES lists: a plain allow (or `context.tes.list_scope: "own"`) lists the caller's tasks, `"all"` every task, and a deny (or `"none"`) gives an empty list. Only a policy you write answers `all`.

### Upgrade notes

**Service clients in the policy data** (PR_REF, not breaking):

- The policy data has a new optional field, `service_clients`. Data without it decides as before: no service client may create tasks. Add your service clients there instead of giving them an entitlement or an exemption in the TES.
- OpenFGA: deploy the model, the setup job and the shim together. The model has a `service_client` relation (condition `listed_client`) and a `may_create` union of `creator` and `service_client`; the shim always sends `subject_iss`, `subject_sub` and `subject_client_id` (empty strings when missing), so `FGA_CLAIMS` can no longer use the parameter names `iss`, `sub` and `client_id`. A store set up by an older job lacks the `service_client` tuple and its model the relation, so run the new setup job (a new store).

**Owner only and `tes-authzen/3`** ([#23](https://github.com/elixir-cloud-aai/tes-authz/issues/23), breaking):

- TESes on `/3` ask the decision service on `CreateTask` only, unless you switch further operations on (`authz.operations`). They send the caller as `resource.properties.owner` on `CreateTask`; this version of the decision services denies a `/3` `CreateTask` without it. A switched-on `ListTasks` that is denied gives an empty list (`200`), not `403`.

- Remove `admins` from your policy data. With it, OPA denies every request and the OpenFGA setup job refuses to start (`the policy data file has 'admins'`), so that nobody assumes admins still see other tasks.
- `members` now means "may create tasks" only. Owners keep get, cancel and their own list after their entitlement is revoked (it was the other way round before, spec Q11); users without the entitlement get an empty list instead of `403`.
- Callers with an admin entitlement lose access to other owners' tasks and to `ListTasks` on `all`. If you relied on it, inspect tasks through the infrastructure instead.
- TES hooks built against the earlier contract (asking about foreign and missing tasks, asking `all`, gating every action with the claim rule) don't meet it; update them before relying on the owner-only rule. Funnel with any `authz.*` key set needs `TaskAccess: Owner`.
- The decision services accept `tes-authzen/3` (and still `/1` and `/2`). Deploy this version before a TES switches to `/3`; an older one denies every `/3` request. A `/3` request on `tes_task_set:all` is a contract error (deny).
- OpenFGA: deploy the model, the setup job and the shim together. The model has no `admin` relation, no `member` relation on `tes_service`, no `entitled_undelegated` condition, and the `own` lister tuple has no condition. The shim no longer sends `subject_delegated` and no longer reserves the `FGA_CLAIMS` parameter name `delegated`; a store set up by an older job still has admin and `all` tuples, so run the new setup job (a new store) rather than reusing it.

**`tes-authzen/2`** ([#19](https://github.com/elixir-cloud-aai/tes-authz/issues/19)): a decision service without `tes-authzen/2` support denies every `tes-authzen/2` request (`decision: false`, so Poiesis answers `403` or `404`). Deploy a commit with it before Poiesis sends `/2`, and on every instance behind the Service.

## OpenFGA mapping (shim)

| AuthZEN in | OpenFGA out |
|---|---|
| `subject` | `user:h-<sha256(subject.id)>`, properties `id` = the real ID, `iss`, `sub` and `client_id` (strings; `""` when missing or not a string), and `entitlements` (list) from the policy's `entitlement_claim` |
| `tes_task:<id>` | `tes_service:<service>`, properties `owner` (`""` when absent) and `images` (`[""]` when the task projection or its executor list is missing or malformed, so an allowlist denies) |
| `tes_task_set:<own\|all>` | `tes_task_set:<service>/<own\|all>`, same properties (`all` has no tuples, so it is denied) |
| `action.name` | the relation of the same name |

OpenFGA turns properties into the condition parameters `subject_id`, `subject_iss`, `subject_sub`, `subject_client_id`, `subject_entitlements`, `resource_owner` and `resource_images`. The shim always sends all of them (review 2, finding 3); `FGA_CLAIMS` can't use the parameter names `id`, `iss`, `sub` and `client_id`. Ownership is the condition `is_owner` on a `user:*` tuple. Membership is the condition `entitled` on the `creator` tuple of `own`, whose tuple context holds the allowed values and prefixes from the data file. Service clients are the condition `listed_client` on the `service_client` tuple of `own`, whose context holds one `"<iss> <client_id>"` string per listed client (joined by one space, which neither value may contain; OpenFGA refuses control characters such as a newline in tuple context values); `CreateTask` is `(creator or service_client) and image_ok`. On `tes_service`, `GetTask` and `CancelTask` are `owner`; `ListTasks` on `own` is an unconditioned `user:*` tuple.

The shim scopes task sets per service (`<service>/own`). That way an unknown `service_id` is denied by both engines alike. Spec [§7](specification.md#7-reference-decision-service-and-engines) only names the `tes_service` rewrite for tasks, so this is a small addition.

## Owner rule

Owners read, list and cancel their own tasks with or without a current entitlement (spec Q11, revised to option (a)); the entitlement only decides who may create tasks. An operator who wants access to end with the entitlement adds `member` to the owner branch in their copy of the policy (OPA: the `GetTask`/`CancelTask` rule and the `own` list; OpenFGA: `owner and member`, with a `member` relation and tuple); the TES's claim rule doesn't do it, since it gates `CreateTask` only. Golden cases `get-own-no-entitlement`, `get-own-near-miss`, `cancel-own-no-entitlement`, `list-own-no-claim`, `get-other-no-entitlement` and the `*-admin*` rows.

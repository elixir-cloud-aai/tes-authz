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
- `members` and `admins`: exact `values` and raw string `prefixes` of the entitlements. Members create tasks and list, read and cancel their own; admins read, list and cancel all tasks, but create tasks only if they are members too, so list the admin group under `members` as well if admins should run tasks. With no admin `values` and `prefixes`, nobody sees other callers' tasks: everyone reads, lists and cancels only their own.
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

The policy implements spec [§7](specification.md#7-reference-decision-service-and-engines) with LS Login entitlements:

| Action | Resource | Allowed if |
|---|---|---|
| `CreateTask` | `tes_task_set:own` | the caller is a member (exact group, or a subgroup via the `…:example-vo:` prefix) and every executor image starts with an allowed prefix (an empty prefix list allows any image) |
| `GetTask`, `CancelTask` | `tes_task:<id>` | the caller is a member and `resource.properties.owner == subject.id` (owner present and not empty), or the caller is an admin; a missing or legacy owner: admins only. Owners need a current entitlement: revoking it ends their access at once (spec Q11, option b) |
| `ListTasks` | `tes_task_set:own` | the caller is a member |
| `ListTasks` | `tes_task_set:all` | the caller is an admin |

An admin needs an admin entitlement and must not be a delegated token (an `actor` key in `subject.properties`, sent from `tes-authzen/2` on): a delegated token of an admin has member powers only. The policy applies this under every profile, also to a `/1` request with an `actor`.

Anything else is denied, and so is any request with a profile other than `tes-authzen/1` and `tes-authzen/2` or an unknown `service_id`.

Poiesis sends `tes-authzen/2` (spec [§12](specification.md#12-tes-authzen2-delta-to-1)). The reference policy decides it like `/1` and ignores the additions, with these consequences for Poiesis (checked against Poiesis 0fa56aa; see its [authorization docs](https://github.com/JaeAeich/poiesis/blob/milestone/docs/app/docs/concepts/authorization.md)):

- **Delegated tokens** (`subject.properties.actor`, under every profile) keep their subject's member powers but never get admin powers, as in Poiesis without a decision service (which also refuses delegated tokens unless the actor is in the issuer's `actors`). The policy doesn't look at who the actor is: if your issuers mint delegated tokens (RFC 8693 token exchange) for actors you don't trust with member powers, deny them in your policy.
- **API keys** (`via: apikey`) carry the claims snapshot taken when the key was minted, and the policy ignores `key_age` and `snapshot_age`. Revoking an entitlement therefore ends the access of that user's keys only when they expire (Poiesis `auth.apiKeys.maxTtl`), not at once as for tokens (spec Q11). Shorten the key lifetime, or refuse old snapshots in your policy.
- **Admins** see other owners' tasks only if Poiesis's `authz.sharing` is on: with it off, Poiesis never asks `ListTasks` on `all` or about other owners' tasks.
- **API keys of other owners**: the policy denies `RevokeApiKeys` and `ListApiKeys` on `poiesis_api_keys`, so admins can't list or revoke other owners' keys while Poiesis uses it. Callers still list and revoke their own keys, as long as they don't pass `?owner=` (with it, even for their own owner, Poiesis asks and is denied).
- **Responses**: the policy never answers with a `context.tes`, so Poiesis's `scope` and `groups` sharing stays unused.

To change any of this, extend the policy.

**Upgrade order**: a decision service without `tes-authzen/2` support (before [#19](https://github.com/elixir-cloud-aai/tes-authz/issues/19)) denies every `tes-authzen/2` request (`decision: false`, so Poiesis answers `403` or `404`). Deploy a commit with it before Poiesis sends `/2`, and on every instance behind the Service. The OpenFGA setup job and shim must come from the same version: the new admin tuples need the `subject_delegated` parameter that only the new shim sends. When you upgrade from a shim before [#19](https://github.com/elixir-cloud-aai/tes-authz/issues/19): the new shim also reserves the parameter name `delegated` (as it did `id`), so an `FGA_CLAIMS` entry `delegated=<claim>` makes it fail at start (`ValueError: bad FGA_CLAIMS entry`). Only a shim started with `FGA_STORE_ID` and no state file can have such an entry; with a state file, `FGA_CLAIMS` must match the policy data file anyway. Rename such an entry, and the condition parameter `subject_delegated` it fed in your OpenFGA model, before you upgrade.

## OpenFGA mapping (shim)

| AuthZEN in | OpenFGA out |
|---|---|
| `subject` | `user:h-<sha256(subject.id)>`, properties `id` = the real ID, and `entitlements` (list) from the policy's `entitlement_claim` |
| `tes_task:<id>` | `tes_service:<service>`, properties `owner` (`""` when absent) and `images` (`[""]` when the task projection or its executor list is missing or malformed, so an allowlist denies) |
| `tes_task_set:<own\|all>` | `tes_task_set:<service>/<own\|all>`, same properties |
| `action.name` | the relation of the same name |

OpenFGA turns properties into the condition parameters `subject_id`, `subject_entitlements`, `subject_delegated` (whether the subject has an `actor`), `resource_owner` and `resource_images`. The shim always sends all five (review 2, finding 3); `FGA_CLAIMS` can't use the parameter names `id` and `delegated`. Ownership is the condition `is_owner` on a `user:*` tuple. Membership is the condition `entitled`, admin rights the condition `entitled_undelegated` (`entitled` and not delegated), on `user:*` tuples whose tuple context holds the allowed values and prefixes from the data file. On `tes_service`, `GetTask` and `CancelTask` are `(owner and member) or admin`, with a `member` relation carrying the members' `entitled` tuple.

The shim scopes task sets per service (`<service>/own`). That way an unknown `service_id` is denied by both engines alike. Spec [§7](specification.md#7-reference-decision-service-and-engines) only names the `tes_service` rewrite for tasks, so this is a small addition.

## Owner rule

Owner rule (Q11, decided option b): owners read and cancel their own tasks only while they hold a member entitlement, so in a PDP-only deployment revoking the entitlement ends access at once, as the claim rule does when it is set. An operator who wants owners to keep access after leaving the group drops `member` from the owner branch in their copy of the policy (OPA: `owner_or_admin`; OpenFGA: `owner and member`). Golden cases `get-own-no-entitlement`, `get-own-near-miss`, `cancel-own-no-entitlement`, `get-other-no-entitlement` and `get-own-admin`. Because `is_owner` now sits inside `owner and member`, a request from a non-member that lacks `resource_owner` or `subject_id` may get a plain deny from OpenFGA instead of the 400 of finding F1; it is never an allow, and the shim always sends both parameters, so the shim, not OpenFGA, guarantees them.

# TES AuthZ

**`tes-authzen/1`** is a specification for authorizing requests to GA4GH Task Execution Service (TES) implementations: a TES asks an external decision service, over [AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html), whether a caller may create, read, list or cancel tasks, so that access policy lives in one place instead of in every TES. The specification is a **draft** (draft 3, accepted for implementation on 2026-11-16): read it on the [Specification](specification.md) page (source: [`spec/tes-authzen-1.md`](https://github.com/elixir-cloud-aai/tes-authz/blob/dev/spec/tes-authzen-1.md)). Its extension `tes-authzen/2`, which Poiesis sends, is described in [§12](specification.md#12-tes-authzen2-delta-to-1), and the current profile `tes-authzen/3` (operations switched on per deployment, owner on create, list scope, no task set `all` in requests) in [§13](specification.md#13-tes-authzen3-delta-to-2).

A TES keeps authentication (OIDC), an owner stamped on every task, and a thin hook that asks one standard AuthZEN Access Evaluation per decision; everything that is policy lives in a decision service of the operator's choice. By default a TES asks the decision service only on create and returns, lists and cancels only the caller's own tasks itself (owner only; no admin views, sharing belongs in clients); operators can hand further operations to the decision service, which then decides them alone. Without configuration, every TES behaves as today. The specification covers:

- [§3 The contract](specification.md#3-the-contract-authzen-mapping): subject, actions, the two resource types, context, list filtering, userinfo and the exact request shape
- [§4 Failure semantics, configuration, security](specification.md#4-failure-semantics-configuration-security): status codes, configuration keys, startup checks
- [§5 Built-in claim rule and composition](specification.md#5-built-in-claim-rule-and-composition): the optional gate on who may create tasks, ANDed with the decision
- [§6 The hook](specification.md#6-the-hook): pseudo-code and implementation notes for Poiesis, TESK, Funnel and TESP
- [§7 Reference decision service and engines](specification.md#7-reference-decision-service-and-engines): the reference policy and how OPA, OpenFGA, Cedar, Casbin, Cerbos and Topaz plug in
- [§8 Test plan](specification.md#8-test-plan): test layers and the shared conformance cases
- [§10 Decisions](specification.md#10-decisions) and [§11 Open questions](specification.md#11-open-questions)
- [§12 `tes-authzen/2`](specification.md#12-tes-authzen2-delta-to-1): the extension Poiesis sends (authenticator, actor and API key properties, response context; task sharing marked as Poiesis extensions outside the contract)
- [§13 `tes-authzen/3`](specification.md#13-tes-authzen3-delta-to-2): the current profile: operations switched on per deployment, owner on create, list scope, no task set `all` in requests

## Reference tooling

Around the specification, this repository holds **reference tooling**: decision services for OPA and OpenFGA behind the `tes-authzen/1` endpoint (they accept `tes-authzen/2` and `/3` too), the shims they need, and a conformance harness that TES implementations plug into (Poiesis first, then TESK, Funnel and TESP). Phase 1 covers OPA and OpenFGA.

Decisions the tooling applies (from the spec's open questions):

- Q1: the claim rule reads the token first, then userinfo.
- Q3: 503 when the decision service fails.
- Q10: the claim rule and the decision are ANDed.

### Architecture

```text
            TES (thin hook)                         decision service (PDP)
 ┌──────────────────────────────┐   AuthZEN 1.0   ┌───────────────────────────────────────────┐
 │ OIDC AuthN, owner stamping,  │  POST /access/  │ opa-front (shim) ─► OPA (Rego + data file) │
 │ claim rule, one evaluation   ├──v1/evaluation─►│ openfga-shim     ─► OpenFGA (model+tuples) │
 │ per decision, owner filter   │                 │ stub (recording, scripted; layer 1 tests) │
 └──────────────────────────────┘                 └───────────────────────────────────────────┘
```

Every engine sits behind the same AuthZEN endpoint, so a TES can't tell them apart. All policy lives in the engine. The shims do only generic, policy-free steps (`shims/common.py`):

- **Contract validation**: profile `tes-authzen/1`, `/2` or `/3`, `subject.type == "user"`, the four actions, the two resource types, the set IDs `own`/`all` (`own` only under `/3`), and a `service_id`. A request that fails it is denied, not answered with an error.
- **Prefix expansion** (`expand_prefixes`): for engines without quantifiers (Cedar, Casbin). Neither phase-1 engine needs it (see the findings).
- **Claim normalisation** (`string_list`): a string becomes a one-element list; other types become an empty list.
- **Identifier encoding** (`encode_id`, `hash_id`): for engines with identifier limits.
- **Fail closed**: an engine error gives `502`, which the TES turns into `503`.

| Path | What |
|---|---|
| `config/reference-policy.json` | **The one place to configure the policy**: entitlement claim, the member entitlements that may create tasks (exact values + `:`-terminated prefixes; there are no admins: an `admins` key makes OPA deny everything and the OpenFGA setup job refuse to start), executor image prefixes, service IDs. OPA loads it as data; the OpenFGA setup job generates the tuples and the shim's claim map from it (a disagreeing `FGA_CLAIMS` refuses to start). |
| `engines/opa/policy/tes_authz.rego` | The reference policy in Rego. It enforces the contract itself too (except the UTF-8 check, which only the front makes), so OPA gives the same golden decisions without the front. |
| `shims/opa_front.py` | Thin AuthZEN front: request → `POST /v1/data/tes/authz/allow` → `{"decision": bool}` |
| `engines/openfga/model.fga`, `model.json` | The OpenFGA model (DSL to read, JSON to load; a test checks that they agree). |
| `engines/openfga/setup.py` | Creates the store, writes the model, generates the tuples from the data file, and records the IDs for the shim. |
| `shims/openfga_shim.py` | The thin shim from spec [§7](specification.md#7-reference-decision-service-and-engines) (mapping below). |
| `stub/recording_pdp.py` | Recording stub PDP with a control API, for hook conformance (layer 1). |
| `oidc/issuer.py`, `oidc/minijose.py` | Mock OIDC issuer (two issuers, `a` and `b`) with a control API: discovery, JWKS with scriptable rotation, RS256 JWT and opaque access tokens, userinfo in JSON and JWT mode, scripted userinfo failures. Standard library only (test-only RSA; see [Mock OIDC issuer](adding-a-tes.md#mock-oidc-issuer)). |
| `harness/oidc.py` | Client for the issuer: `OIDC.token_for(identity)` for adapters, plus key rotation and userinfo scripting for tests. |
| `golden/` | Golden AuthZEN requests with expected decisions (`requests/`, generated from the spec's conformance cases; `<tes>/`, recorded by a TES's own hook tests, e.g. `poiesis/`), the hook-side golden `create` request (`hook/`) and the URL stripping cases. |
| `harness/` | Engine registry, golden loading and diffing, stub client, TES-under-test interface. |
| `tes/mock/` | An in-process mock TES with the hook (test-only; executable form of the spec [§6](specification.md#6-the-hook) pseudo-code), with OIDC AuthN against the mock issuer and the optional userinfo lookup of spec [§3.6](specification.md#36-userinfo-identity-resolution-in-the-tes). |
| `compose.yaml` | The engines, shims, stub, mock OIDC issuer and setup job, with pinned images, `tes-authz-*` container names and loopback ports. |

### What phase 2 needs

- **Mock OIDC issuer:** done (`oidc/`, compose service `oidc`; see [Add a TES](adding-a-tes.md)). Every adapter still needs its `token()` and OIDC wiring.
- **Adapters** for Poiesis (kind), TESK (kind), Funnel and TESP (compose), each mapping `HookConfig` onto its configuration keys (spec [§4.2](specification.md#42-configuration-keys)).
- **Cases the mock TES can't exercise:** 1 and 22 per TES; 23 and 23b (startup refusals); 24 (Funnel over gRPC, with grpcurl or a Go test). Add them to `tests/conformance/` gated on adapter `features`, and give case 22 a per-TES expectation (today it runs for `mock` only). The userinfo cases 6b, 20 and 21 are in the suite and run for every adapter with the `userinfo` feature.
- **More golden requests from each TES** in `golden/<tes>/`, like Poiesis's in `golden/poiesis/` (the harness reads every such directory): each needs a `reference_policy` expectation (in the wrapper or in `golden/expectations.json`), its service ID in the policy's `services`, and placeholders for owner and issuer values.
- **A home and CI:** done: this repository; the `Integration` job of the `CI` workflow runs `make test` (Docker, with the images of `compose.yaml`).
- **Further engines when needed:** Cedar and Casbin (they use `expand_prefixes`), Cerbos and Topaz (whose behaviour is still unverified).

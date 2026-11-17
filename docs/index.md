# TES AuthZ: engine side

Reference decision services, shims and a test harness for the TES AuthZ contract `tes-authzen/1`, as specified in `../spec.md` (draft 3). Phase 1 covers OPA and OpenFGA, with the harness the TES side plugs into (Poiesis first, then TESK, Funnel and TESP).

Decisions applied (from the spec's open questions):

- Q1: the claim rule reads the token first, then userinfo.
- Q3: 503 when the decision service fails.
- Q10: the claim rule and the decision are ANDed.

## Architecture

```text
            TES (thin hook)                         decision service (PDP)
 ┌──────────────────────────────┐   AuthZEN 1.0   ┌───────────────────────────────────────────┐
 │ OIDC AuthN, owner stamping,  │  POST /access/  │ opa-front (shim) ─► OPA (Rego + data file) │
 │ claim rule, one evaluation   ├──v1/evaluation─►│ openfga-shim     ─► OpenFGA (model+tuples) │
 │ per decision, list scope     │                 │ stub (recording, scripted; layer 1 tests) │
 └──────────────────────────────┘                 └───────────────────────────────────────────┘
```

Every engine sits behind the same AuthZEN endpoint, so a TES can't tell them apart. All policy lives in the engine. The shims do only generic, policy-free steps (`shims/common.py`):

- **Contract validation**: profile `tes-authzen/1`, `subject.type == "user"`, the four actions, the two resource types, the set IDs `own`/`all`, and a `service_id`. A request that fails it is denied, not answered with an error.
- **Prefix expansion** (`expand_prefixes`): for engines without quantifiers (Cedar, Casbin). Neither phase-1 engine needs it (see the findings).
- **Claim normalisation** (`string_list`): a string becomes a one-element list; other types become an empty list.
- **Identifier encoding** (`encode_id`, `hash_id`): for engines with identifier limits.
- **Fail closed**: an engine error gives `502`, which the TES turns into `503`.

| Path | What |
|---|---|
| `config/reference-policy.json` | **The one place to configure the policy**: entitlement claim, member and admin entitlements (exact values + `:`-terminated prefixes), executor image prefixes, service IDs. OPA loads it as data; the OpenFGA setup job generates the tuples and the shim's claim map from it (a disagreeing `FGA_CLAIMS` refuses to start). |
| `engines/opa/policy/tes_authz.rego` | The reference policy in Rego. It enforces the contract itself too (except the UTF-8 check, which only the front makes), so OPA gives the same golden decisions without the front. |
| `shims/opa_front.py` | Thin AuthZEN front: request → `POST /v1/data/tes/authz/allow` → `{"decision": bool}` |
| `engines/openfga/model.fga`, `model.json` | The OpenFGA model (DSL to read, JSON to load; a test checks that they agree). |
| `engines/openfga/setup.py` | Creates the store, writes the model, generates the tuples from the data file, and records the IDs for the shim. |
| `shims/openfga_shim.py` | The thin shim from spec §7 (mapping below). |
| `stub/recording_pdp.py` | Recording stub PDP with a control API, for hook conformance (layer 1). |
| `oidc/issuer.py`, `oidc/minijose.py` | Mock OIDC issuer (two issuers, `a` and `b`) with a control API: discovery, JWKS with scriptable rotation, RS256 JWT and opaque access tokens, userinfo in JSON and JWT mode, scripted userinfo failures. Standard library only (test-only RSA; see [Mock OIDC issuer](adding-a-tes.md#mock-oidc-issuer)). |
| `harness/oidc.py` | Client for the issuer: `OIDC.token_for(identity)` for adapters, plus key rotation and userinfo scripting for tests. |
| `golden/` | Golden AuthZEN requests with expected decisions, the hook-side golden `create` request and the URL stripping cases. |
| `harness/` | Engine registry, golden loading and diffing, stub client, TES-under-test interface. |
| `tes/mock/` | An in-process mock TES with the hook (test-only; executable form of the spec §6 pseudo-code), with OIDC AuthN against the mock issuer and the optional userinfo lookup of spec §3.6. |
| `compose.yaml` | The engines, shims, stub, mock OIDC issuer and setup job, with pinned images, `tes-authz-*` container names and loopback ports. |

## What phase 2 needs

- **Mock OIDC issuer:** done (`oidc/`, compose service `oidc`; see [Add a TES](adding-a-tes.md)). Every adapter still needs its `token()` and OIDC wiring.
- **Adapters** for Poiesis (kind), TESK (kind), Funnel and TESP (compose), each mapping `HookConfig` onto its configuration keys (spec §4.2).
- **Cases the mock TES can't exercise:** 1 and 22 per TES; 13b (scope-bound cursor, TESK 400); 23 (startup refusal); 24 (Funnel over gRPC, with grpcurl or a Go test). Add them to `tests/conformance/` gated on adapter `features`, and give case 22 a per-TES expectation (today it runs for `mock` only). The userinfo cases 6b, 20 and 21 are in the suite and run for every adapter with the `userinfo` feature.
- **More golden requests from each TES** in `tes-authz/golden/<tes>/`, like Poiesis's: each needs a `reference_policy` expectation (in the wrapper or in `golden/expectations.json`), its service ID in the policy's `services`, and placeholders for owner and issuer values.
- **A home and CI:** done: this repository; the `Integration` job of the `CI` workflow runs `make test` (Docker, with the images of `compose.yaml`).
- **Further engines when needed:** Cedar and Casbin (they use `expand_prefixes`), Cerbos and Topaz (whose behaviour is still unverified).

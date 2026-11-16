# TES AuthZ: engine side (phase 1)

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
| `config/reference-policy.json` | **The one place to configure the policy**: entitlement claim, member and admin entitlements (exact values + `:`-terminated prefixes), executor image prefixes, service IDs. Both engines load it. |
| `engines/opa/policy/tes_authz.rego` | The reference policy in Rego. It enforces the contract itself too, so OPA is safe to call without the front. |
| `shims/opa_front.py` | Thin AuthZEN front: request → `POST /v1/data/tes/authz/allow` → `{"decision": bool}` |
| `engines/openfga/model.fga`, `model.json` | The OpenFGA model (DSL to read, JSON to load; a test checks that they agree). |
| `engines/openfga/setup.py` | Creates the store, writes the model, generates the tuples from the data file, and records the IDs for the shim. |
| `shims/openfga_shim.py` | The thin shim from spec §7 (mapping below). |
| `stub/recording_pdp.py` | Recording stub PDP with a control API, for hook conformance (layer 1). |
| `golden/` | Golden AuthZEN requests with expected decisions, the hook-side golden `create` request and the URL stripping cases. |
| `harness/` | Engine registry, golden loading and diffing, stub client, TES-under-test interface. |
| `tes/mock/` | An in-process mock TES with the hook (test-only; executable form of the spec §6 pseudo-code). |
| `compose.yaml` | The engines, shims, stub and setup job, with pinned images, `tes-authz-*` container names and loopback ports. |

### Reference policy

The policy implements spec §7 with LS Login entitlements:

| Action | Resource | Allowed if |
|---|---|---|
| `CreateTask` | `tes_task_set:own` | the caller is a member (exact group, or a subgroup via the `…:example-vo:` prefix) and every executor image starts with an allowed prefix (an empty prefix list allows any image) |
| `GetTask`, `CancelTask` | `tes_task:<id>` | `resource.properties.owner == subject.id` (owner present and not empty), or the caller is an admin; a missing or legacy owner: admins only |
| `ListTasks` | `tes_task_set:own` | the caller is a member |
| `ListTasks` | `tes_task_set:all` | the caller is an admin |

Anything else is denied, and so is any request with another profile or an unknown `service_id`.

### OpenFGA mapping (shim)

| AuthZEN in | OpenFGA out |
|---|---|
| `subject` | `user:h-<sha256(subject.id)>`, properties `id` = the real ID, and `entitlements` (list) per `FGA_CLAIMS` |
| `tes_task:<id>` | `tes_service:<service>`, properties `owner` (`""` when absent) and `images` (`[]`) |
| `tes_task_set:<own\|all>` | `tes_task_set:<service>/<own\|all>`, same properties |
| `action.name` | the relation of the same name |

OpenFGA turns properties into the condition parameters `subject_id`, `subject_entitlements`, `resource_owner` and `resource_images`. The shim always sends all four (review 2, finding 3). Ownership is the condition `is_owner` on a `user:*` tuple. Membership and admin rights are the condition `entitled` on `user:*` tuples, whose tuple context holds the allowed values and prefixes from the data file.

The shim scopes task sets per service (`<service>/own`). That way an unknown `service_id` is denied by both engines alike. Spec §7 only names the `tes_service` rewrite for tasks, so this is a small addition.

## Run it

Needs Docker with Compose, `uv` and `make`. Everything stays inside this folder: the virtual environment in `.venv/` and the uv cache in `.cache/`.

```sh
make test     # lint, types, `opa check`, start services, all suites, stop and remove
make up       # start only (ports 18080 OpenFGA, 18181 OPA, 18190 OPA front, 18191 OpenFGA shim, 18192 stub)
make unit     # tests that need no containers
make down     # stop and remove containers and the state volume
```

`scripts/test.sh [pytest args]` is what `make test` runs. Set `TES_AUTHZ_KEEP=1` to leave the services running afterwards, and `TES_AUTHZ_<NAME>_PORT` to move ports. Try an evaluation by hand with `make up`, then:

```sh
curl -s localhost:18190/access/v1/evaluation -d @<(jq .request golden/requests/create-member-subgroup.json)
```

## Tests

| Layer (spec §8.1) | File | What | Phase-1 result |
|---|---|---|---|
| unit | `tests/test_common.py` | URL stripping (13 golden cases), prefix expansion vs `startswith`, validation, OpenFGA mapping | 31 pass |
| golden | `tests/test_golden.py` | golden files match the generator, every case has an expectation, allowed cases follow the profile | 3 pass |
| 2: engine conformance | `tests/test_engines.py` | 53 golden requests × {OPA via front, OPA Data API, OpenFGA via shim} | 159 pass |
| findings | `tests/test_findings.py`, `test_openfga_model.py` | engine behaviours the spec marked unverified (below) | 17 pass |
| 1: hook conformance | `tests/conformance/test_hook.py` | spec cases 2, 4b, 5, 5b, 5c, 5d, 7, 7b, 8, 9, 10, 10b, 11, 11b, 12, 13, 14, 15 (×5 failure kinds), 16, 17, 18, 19, 22 against the stub | 28 pass (mock TES) |
| 3: smoke | `tests/conformance/test_smoke.py` | TES × {OPA, OpenFGA}: allow, deny, foreign get 404, missing get and cancel 404, list scopes | 2 pass (mock TES) |

Total: 240 passed (`make test`, 2026-11-16, OPA 1.22.4, OpenFGA v1.22.1).

The golden requests cover spec cases 3, 4, 4b, 5, 5d, 6, 7, 9–14 and 17, plus contract checks: missing or wrong profile, unknown service, wrong subject type, unknown set or action. They also cover legacy tasks without an owner, issuer-qualified (`<iss>|<sub>`) and 600-character subject IDs, and task IDs containing `:#@`.

### Where golden requests come from

`tes-authz/golden/` didn't exist when this was built, so `scripts/gen_golden.py` writes the spec's conformance cases as golden requests into `golden/requests/`. The harness also reads every JSON file under `../golden/` (or the directories in `TES_AUTHZ_GOLDEN_DIRS`) once the Poiesis tests write them there. It accepts two formats:

- the wrapper `{"name", "case", "description", "request", "expect": {"reference_policy": {"decision": bool}}}`;
- a bare AuthZEN request, whose expectation goes into `golden/expectations.json` under `{"<dir>/<file stem>": {"reference_policy": {"decision": bool}}}`.

`test_every_golden_case_has_an_expectation` fails for files without one, so a new golden request can't go unchecked. Hook-side golden files (`golden/hook/`) use placeholders such as `{{subject_id}}`, `{{iss}}` and `{{client_id}}`, which each TES adapter fills in.

## Add an engine

1. Add a compose service for the engine, plus a shim if it has no AuthZEN endpoint or needs a mapping. A shim is `common.serve(port, decide, metadata)` with one `decide(request, headers) -> bool`. Reuse `common` for validation, claim normalisation, prefix expansion and identifier encoding.
2. Configure the engine from `config/reference-policy.json`: load it as data, or generate the engine's artefacts from it as `engines/openfga/setup.py` does.
3. Add one `Engine` entry to `harness/engines.py` with its host URL (and its compose-network URL).

The replay (all golden cases), the smoke tests and every TES adapter then pick it up. If the engine's answers differ from the expected decisions, fix the engine-side policy, not the expectations: the expected table is shared by all engines.

## Add a TES (phase 2)

1. Create `tes/<name>/adapter.py` that exposes `ADAPTER`, implementing `harness.tes.TesUnderTest`:
   - `start(HookConfig) -> base URL` maps the config onto the TES's keys (e.g. `POIESIS_AUTHZ_DECISION_SERVICE_URL`) and (re)starts it with an empty store.
   - `token(Identity)` mints a token the TES accepts.
   - `owner_id(Identity)` returns the owner the TES stamps.
   - `subject_fixtures(Identity)` returns `iss` and `client_id` (`None` where the TES can't fill them, e.g. TESK for user tokens).
   - `stop()` stops it.
   - `features` names optional features (`userinfo`, `grpc`, `scope-bound-cursor`, …).
2. Containerised TESes use `Engine.network_url` and join the compose network `tes-authz_default`.
3. Run `TES_AUTHZ_TES=mock,<name> make test`.

The engine side, the stub and the suites stay unchanged.

## Findings: spec claims checked against running software

Results come from OPA 1.22.4 and OpenFGA v1.22.1 (`OPENFGA_EXPERIMENTALS=authzen`), and are pinned by `tests/test_findings.py` and `tests/test_common.py`.

| # | Spec claim | Result | Evidence |
|---|---|---|---|
| F1 | OpenFGA returns an error, not a deny, when a condition parameter is missing (§7, review 2 finding 3) | **Verified.** HTTP 400 `validation_error`, "tuple '…' is missing context parameters '[resource_owner]'". Without the always-pass rule, missing and legacy tasks would give 503. With the shim, both give `decision: false` (golden `get-missing`, `get-legacy-no-owner`; smoke: 404 end to end). | `test_openfga_missing_condition_parameter_is_an_error` |
| F2 | `subject.id` is not in OpenFGA's condition context, only `subject_*` properties (§7) | **Verified.** A request with `subject.id` but without `properties.id` fails with "missing … '[subject_id]'". | `test_openfga_subject_id_is_not_in_condition_context` |
| F3 | OpenFGA ID pattern/length limits **[unverified]**; "the shim hashes long IDs" (§7) | **Verified, and stricter than the spec assumes.** Subject IDs must match `^[^:#@\s]{1,500}$` and resource IDs `^[^:#@\s]{1,256}$`. Length isn't the main problem: every `<iss>\|<sub>` owner (has `:`) and every LS Login `sub` (`…@lifescience-ri.eu`, has `@`) is rejected. The shim must hash or encode every subject ID, not only long ones. Ours hashes all of them and passes the real ID as `subject_id`. **Spec text to change:** "the shim hashes long IDs" → "the shim encodes every subject ID (OpenFGA rejects `:`, `#`, `@`, whitespace)". | `test_openfga_identifier_limits` (6 cases), boundaries at 500/256 |
| F4 | Prefix tests need expansion in engines without quantifiers; reference prefixes must end in a delimiter, or expansion and `startswith` disagree (§7) | **Verified.** Expansion equals `startswith` for `:`-terminated prefixes on every golden entitlement set; `urn:g:vo` vs `urn:g:vo2#x` disagrees. **Addition:** OpenFGA's CEL conditions support `exists`/`all` and `startsWith`, so OpenFGA needs no expansion and tests prefixes natively. Expansion stays in `common` for Cedar and Casbin. | `test_prefix_expansion_*`; the OpenFGA model's `entitled` condition |
| F5 | In OpenFGA's AuthZEN, `action.name` must be a relation (§7) | **Verified.** An unknown action gives 400 (it would be a 503 at the TES). The shim validates action names first and denies. | `test_openfga_unknown_relation_is_an_error` |
| F6 | Native AuthZEN PDPs return only `decision` (§3.5) | **Verified** for OpenFGA: the body is exactly `{"decision": …}`. | `test_openfga_answers_decision_only` |
| F7 | `tes_task_set:own/all` work natively in OpenFGA with `user:*` tuples; `tes_task` needs the `tes_service` rewrite with a conditioned `user:*` tuple (§7) | **Verified** by the full golden replay. Design note: OpenFGA allows only one tuple per (object, relation, user), so owner and admin need separate relations (`owner`, `admin`, with `GetTask: owner or admin`). | `test_golden_decision[openfga-*]` |
| F8 | OPA needs a ~50-line shim (§7) | **Verified.** The front is ~60 lines with docstrings. The Rego policy also enforces the contract, so OPA called directly (Data API) gives the same 53 decisions. | `test_golden_decision[opa-data-api-*]` |
| F9 | OpenFGA's AuthZEN endpoint is store-scoped, so v1 config takes the full URL (§2, §7) | **Verified**: `/stores/{id}/access/v1/evaluation`. The shim hides this, so the TES config holds the shim URL. | `fga_eval` fixture |
| F10 | `X-Request-ID` (AuthZEN §10.1.3) | OpenFGA **doesn't echo** a client-supplied ID; both shims do, for log correlation. | `test_openfga_does_not_echo_request_id`, `test_shims_echo_request_id` |

Not checked here: Cedar entity tags, Cerbos role mapping and Topaz directory behaviour (not in phase 1); OpenFGA Search paging (Search isn't used); Passport validation.

Observation for the policy (no spec change needed): under the reference policy, owners read and cancel their own tasks without a current entitlement, as §7 says. When the claim rule is set, it blocks such users before the PDP is asked (AND, Q10). In a PDP-only deployment, a user who has lost the entitlement keeps access to their old tasks. If that's unwanted, add `member` to the owner branch.

## What phase 2 needs

- **Mock OIDC issuer** in compose (discovery, JWKS, userinfo with `application/json` and `application/jwt` modes, and opaque tokens for TESK), and a `token()` in every adapter.
- **Adapters** for Poiesis (kind), TESK (kind), Funnel and TESP (compose), each mapping `HookConfig` onto its configuration keys (spec §4.2).
- **Cases the mock TES can't exercise:** 1 and 22 per TES; 6b, 20 and 21 (userinfo); 13b (scope-bound cursor, TESK 400); 23 (startup refusal); 24 (Funnel over gRPC, with grpcurl or a Go test). Add them to `tests/conformance/` gated on adapter `features`, and give case 22 a per-TES expectation (today it runs for `mock` only).
- **Golden requests from Poiesis** in `tes-authz/golden/`: the harness reads them already. Each needs a `reference_policy` expectation (in the wrapper or in `golden/expectations.json`). Owner and issuer values should use the placeholders.
- **A home and CI:** a repository (uniqueg decides) and a CI job running `make test`. The CI job needs Docker and pulls about 5 images.
- **Further engines when needed:** Cedar and Casbin (they use `expand_prefixes`), Cerbos and Topaz (whose behaviour is still unverified).

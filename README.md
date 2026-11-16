# TES AuthZ: engine side (phase 1)

[![License][badge-license]][badge-url-license]
[![Build_status][badge-build-status]][badge-url-build-status]

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
| `oidc/issuer.py`, `oidc/minijose.py` | Mock OIDC issuer (two issuers, `a` and `b`) with a control API: discovery, JWKS with scriptable rotation, RS256 JWT and opaque access tokens, userinfo in JSON and JWT mode, scripted userinfo failures. Standard library only (test-only RSA; see [Mock OIDC issuer](#mock-oidc-issuer)). |
| `harness/oidc.py` | Client for the issuer: `OIDC.token_for(identity)` for adapters, plus key rotation and userinfo scripting for tests. |
| `golden/` | Golden AuthZEN requests with expected decisions, the hook-side golden `create` request and the URL stripping cases. |
| `harness/` | Engine registry, golden loading and diffing, stub client, TES-under-test interface. |
| `tes/mock/` | An in-process mock TES with the hook (test-only; executable form of the spec §6 pseudo-code), with OIDC AuthN against the mock issuer and the optional userinfo lookup of spec §3.6. |
| `compose.yaml` | The engines, shims, stub, mock OIDC issuer and setup job, with pinned images, `tes-authz-*` container names and loopback ports. |

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
| `subject` | `user:h-<sha256(subject.id)>`, properties `id` = the real ID, and `entitlements` (list) from the policy's `entitlement_claim` |
| `tes_task:<id>` | `tes_service:<service>`, properties `owner` (`""` when absent) and `images` (`[""]` when the task projection or its executor list is missing or malformed, so an allowlist denies) |
| `tes_task_set:<own\|all>` | `tes_task_set:<service>/<own\|all>`, same properties |
| `action.name` | the relation of the same name |

OpenFGA turns properties into the condition parameters `subject_id`, `subject_entitlements`, `resource_owner` and `resource_images`. The shim always sends all four (review 2, finding 3). Ownership is the condition `is_owner` on a `user:*` tuple. Membership and admin rights are the condition `entitled` on `user:*` tuples, whose tuple context holds the allowed values and prefixes from the data file.

The shim scopes task sets per service (`<service>/own`). That way an unknown `service_id` is denied by both engines alike. Spec §7 only names the `tes_service` rewrite for tasks, so this is a small addition.

## Run it

Needs Docker with Compose, `uv` and `make`. Everything stays inside this folder: the virtual environment in `.venv/` and the uv cache in `.cache/`.

This compose file is a local test and reference setup. All containers are read-only, drop all capabilities and run without new privileges, and ports bind to loopback only. But OPA's and OpenFGA's own APIs (18181, 18080) are published for the findings tests and are **not authenticated**: any local process can change policy data or tuples. A deployment publishes only the shims and enables OPA token authorization and OpenFGA preshared keys.

```sh
make test     # lint, types, `opa check`, start services, all suites, stop and remove
make up       # start only (ports 18080 OpenFGA, 18181 OPA, 18190 OPA front, 18191 OpenFGA shim, 18192 stub, 18193 OIDC)
make unit     # tests that need no containers
make down     # stop and remove containers and the state volume
```

`scripts/test.sh [pytest args]` is what `make test` runs. Set `TES_AUTHZ_KEEP=1` to leave the services running afterwards. Try an evaluation by hand with `make up`, then:

```sh
curl -s localhost:18190/access/v1/evaluation -d @<(jq .request golden/requests/create-member-subgroup.json)
```

### One stack per worktree

Each worktree can run its own stack next to the others. Two variables, read by `make`, `scripts/test.sh`, compose and the harness (`harness/stack.py`), select it:

| Variable | Default (main checkout) | Effect |
|---|---|---|
| `TES_AUTHZ_PROJECT` | `tes-authz` | compose project, container names `<project>-opa`, `<project>-oidc`, …, network `<project>_default` |
| `TES_AUTHZ_PORT_BASE` | `18080` | host ports: OpenFGA base+0, OPA +101, OPA front +110, OpenFGA shim +111, stub +112, OIDC +113 (so the defaults are 18080, 18181, 18190–18193) |

`TES_AUTHZ_<NAME>_PORT` (e.g. `TES_AUTHZ_OIDC_PORT`) still moves a single port. Keep port bases at least 200 apart. Export both variables in the shell that runs `make` and pytest, so that `make test`, `make up`/`make down` and a direct `pytest` all address the same stack. `make down` and the cleanup in `make test` remove only that project's containers. The values for the phase-2 worktrees are in `PHASE2-STACKS.md`.

## Tests

| Layer (spec §8.1) | File | What | Phase-1 result |
|---|---|---|---|
| unit | `tests/test_common.py` | URL stripping (28 golden rows of the six-step rule with step 2b, spec §3.3; identical to `../golden/poiesis/url-stripping.json`), prefix expansion vs `startswith`, validation, OpenFGA mapping | 46 pass |
| golden | `tests/test_golden.py` | golden files match the generator, every case has an expectation, allowed cases follow the profile | 3 pass |
| 2: engine conformance | `tests/test_engines.py` | 71 golden requests (65 generated + 6 recorded by Poiesis in `../golden/poiesis/`) × {OPA via front, OPA Data API, OpenFGA via shim} | 213 pass |
| findings | `tests/test_findings.py`, `test_openfga_model.py` | engine behaviours the spec marked unverified (below), shim hardening | 21 pass |
| 1: hook conformance | `tests/conformance/test_hook.py` | spec cases 2, 4b, 5, 5b, 5c, 5d, 7, 7b, 8, 9, 10, 10b, 11, 11b, 11c (cancel parity), 12, 13, 14, 15 (×5 failure kinds on create, plus get, cancel and list), 16, 17, 18, 19, 22, and the exact request shape of §3.7, against the stub; userinfo cases 6b, 20 (×5: `sub` mismatch, 500, dropped connection, timeout, `application/jwt`) and 21 for adapters with the `userinfo` feature | 41 pass (mock TES) |
| 3: smoke | `tests/conformance/test_smoke.py` | TES × {OPA, OpenFGA}: allow, deny, foreign get 404, missing get and cancel 404, list scopes | 2 pass (mock TES) |
| OIDC: issuer | `tests/test_oidc_issuer.py`, `tests/test_oidc_jose.py` | the mock issuer itself (in-process, plus one check of the compose service): discovery per host name, JWKS, rotation and retirement, opaque tokens, userinfo modes and failures, control API validation; RS256 cross-checked with PyJWT + `cryptography` in both directions | 73 pass |
| OIDC: mock TES AuthN | `tests/conformance/test_mock_oidc.py` | the mock TES refuses `alg: none`, unpublished keys, wrong audience, expired tokens, another issuer, forged `iss`, unknown `kid`, opaque tokens; accepts tokens after a rotation (JWKS refetch); stamps `<iss>\|<sub>` owners when pinned to both issuers; no or unreachable issuer, wrong userinfo content type, userinfo cache TTL, LRU size and token expiry | 14 pass |
| stack | `tests/test_stack.py` | per-worktree project and port block: defaults, base and overrides, project name check, the exports script, compose uses every port variable | 9 pass |

Total: 422 passed (`make test`, 2026-11-16, OPA 1.22.4, OpenFGA v1.22.1).

The golden requests cover spec cases 3, 4, 4b, 5, 5d, 6, 7, 9–14 and 17, plus contract checks: missing or wrong profile, unknown service, wrong subject type, unknown set or action. They also cover legacy tasks without an owner, issuer-qualified (`<iss>|<sub>`) and 600-character subject IDs, and task IDs containing `:#@`. Realistic sizes: 1024 entitlements with the match last, 1023 non-matching ones, 1024 executors (all allowed, or the last denied). Malformed projections (executors as object, string or null; entries without image; no task) are denied when an image allowlist is set.

### Where golden requests come from

`tes-authz/golden/` didn't exist when this was built, so `scripts/gen_golden.py` writes the spec's conformance cases as golden requests into `golden/requests/`. The harness also reads every JSON file under `../golden/` (or the directories in `TES_AUTHZ_GOLDEN_DIRS`). Since then, the Poiesis hook tests have written 6 requests to `../golden/poiesis/`; they're replayed too, and agree with both engines. They use Poiesis's service ID `org.ga4gh.poiesis`, which is therefore in the policy's `services`. It accepts two formats:

- the wrapper `{"name", "case", "description", "request", "expect": {"reference_policy": {"decision": bool}}}`;
- a bare AuthZEN request, whose expectation goes into `golden/expectations.json` under `{"<label>/<file stem>": {"reference_policy": {"decision": bool}}}`, where the label is the directory relative to `tes-authz/` (e.g. `golden`). A non-boolean `decision` or two files with the same name fail loading.

`test_every_golden_case_has_an_expectation` fails for files without one, so a new golden request can't go unchecked. Hook-side golden files (`golden/hook/`) use placeholders such as `{{subject_id}}`, `{{iss}}` and `{{client_id}}`, which each TES adapter fills in.

## Add an engine

1. Add a compose service for the engine, plus a shim if it has no AuthZEN endpoint or needs a mapping. A shim is `common.serve(port, decide, metadata)` with one `decide(request, headers) -> bool`. Reuse `common` for validation, claim normalisation, prefix expansion and identifier encoding.
2. Configure the engine from `config/reference-policy.json`: load it as data, or generate the engine's artefacts from it as `engines/openfga/setup.py` does.
3. Add one `Engine` entry to `harness/engines.py` with its host URL (and its compose-network URL).

The replay (all golden cases), the smoke tests and every TES adapter then pick it up. If the engine's answers differ from the expected decisions, fix the engine-side policy, not the expectations: the expected table is shared by all engines.

## Add a TES (phase 2)

1. Create `tes/<name>/adapter.py` that exposes `ADAPTER`, implementing `harness.tes.TesUnderTest`:
   - `start(HookConfig) -> base URL` maps the config onto the TES's keys (e.g. `POIESIS_AUTHZ_DECISION_SERVICE_URL`), wires OIDC (step 2) and (re)starts it with an empty store. `HookConfig.userinfo` maps onto the TES's userinfo switch (`auth.oidc.userinfo.enabled`).
   - `token(Identity)` returns `OIDC.token_for(identity, base=…)` (step 2).
   - `owner_id(Identity)` returns the owner the TES stamps (`identity.sub` for a single-issuer TES).
   - `subject_fixtures(Identity)` returns `iss` (`issuer_url("a", base)`) and `client_id` (`harness.oidc.default_claims(identity)["azp"]` for users, `["client_id"]` for client-credentials identities; `None` where the TES can't fill them, e.g. TESK for user tokens).
   - `stop()` stops it.
   - `features` names optional features (`userinfo`, `userinfo-timeout`, `opaque-tokens`, `grpc`, `scope-bound-cursor`, …). With `userinfo`, cases 6b, 20 and 21 run. Case 20's timeout variant runs only with `userinfo-timeout`: the adapter bounds discovery, JWKS and userinfo calls by `HookConfig.timeout` (the test sets 1 s and delays userinfo by 3 s). With `opaque-tokens` (TESK), case 20's `sub`-mismatch variant is skipped, because there is no token `sub` to compare.
2. OIDC wiring (mock issuer, compose service `oidc`, container `<project>-oidc`, by default `tes-authz-oidc`; ports and names per worktree as in [One stack per worktree](#one-stack-per-worktree)):

   | TES runs | Issuer URL to configure | Mint with |
   |---|---|---|
   | on the host | `issuer_url("a")` = `http://127.0.0.1:<OIDC port>/a` (18193 by default) | `OIDC.token_for(identity)` |
   | on the compose network | `issuer_url("a", NETWORK_BASE)` = `http://<project>-oidc:8080/a` | `OIDC.token_for(identity, base=NETWORK_BASE)` |
   | in kind pods (Poiesis, TESK) | `http://<issuer IP on the kind network>:8080/a` (below) | `OIDC.token_for(identity, base="http://<same IP>:8080")` |

   The issuer publishes its port on host loopback only, which kind pods can't reach. Attach the container to the kind network and use its IP there (verified from a pod in kind v0.33.0: `curl http://<ip>:8080/a/.well-known/openid-configuration` from a `curlimages/curl` pod returns the discovery document with `issuer` `http://<ip>:8080/a`):

   ```sh
   docker network connect kind "$TES_AUTHZ_PROJECT-oidc"
   docker inspect -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}' "$TES_AUTHZ_PROJECT-oidc"
   ```

   Pods reach container IPs on the kind network through their node. The issuer derives its URL from the `Host` header, so `http://<ip>:8080/a` is a consistent issuer as long as tokens are minted with the same `base`. `make down` removes the container and with it the attachment.

   - Audience: `AUDIENCE` (`tes-authz`). Discovery is at `<issuer>/.well-known/openid-configuration`; JWKS, userinfo and the issuer field in discovery follow the host name the TES used, so they stay consistent wherever it runs. Tokens must be minted with the same `base`, because `iss` must match exactly.
   - TESes that validate JWTs (Poiesis, Funnel, TESP) use the default `fmt="jwt"`; TESK, which validates opaque tokens at userinfo only, uses `fmt="opaque"` and declares the `opaque-tokens` feature (userinfo then returns the identity's token claims over its userinfo claims, so the resolved view is the same as for a JWT TES).
   - Multi-issuer setups pin `issuer_url("a", …)` and `issuer_url("b", …)` and mint with `issuer="b"` for the second one; owners are then `<iss>|<sub>`.
   - Negative AuthN cases: `OIDC.mint(sub, base=…, **options)` with `alg="none"`, `key="unpublished"`, `aud=…`, `expires_in=-3600` (real stacks allow 30–60 s of clock skew, so a token that expired a second ago may still pass), `claims={…}`, `header={…}`; key rotation with `OIDC.rotate()`/`OIDC.retire()`. Tests that script the issuer take the `oidc` fixture. It resets tokens, userinfo behaviours and recorded calls, but signing keys survive (a rotation in one test leaves a new active key for the next); call `oidc.reset(keys=True)` when a test needs fresh keys.
3. Containerised TESes use `Engine.network_url` and join the compose network `<project>_default` (`tes-authz_default` by default).
4. Run `TES_AUTHZ_TES=mock,<name> make test`.

The engine side, the stub, the issuer and the suites stay unchanged.

### Mock OIDC issuer

`oidc/issuer.py` serves the issuers `a` and `b` on port 18193 (loopback). Endpoints per issuer: discovery, `jwks`, `userinfo` (GET or POST), and a `token` endpoint that refuses every grant: tokens come from the control API (`POST /_control/tokens`, see the module docstring), so tests choose subject, claims, audience, expiry, scope, key and format directly. Every token, JWT or opaque, also works at userinfo until it expires; userinfo returns `sub` plus the claims given at minting.

Control API: mint tokens; rotate keys (with or without overlap) and retire keys from the JWKS; script userinfo per subject or by default (`mode: jwt` for a signed `application/jwt` answer, `status`, `delay`, `close`, a different `sub`, a different `content_type`); read recorded userinfo calls (token hashes, never tokens); reset. A TES never calls it.

The RSA code (`oidc/minijose.py`) is textbook PKCS #1 v1.5 in the standard library, so the container needs only the pinned Python image, like the shims. It is for tests only. `tests/test_oidc_jose.py` checks it against PyJWT with `cryptography` (a dev dependency) in both directions. Keys are generated at startup (about 1 s for two 2048-bit keys) and live in memory, so a restarted issuer has new keys.

## Findings: spec claims checked against running software

Results come from OPA 1.22.4 and OpenFGA v1.22.1 (`OPENFGA_EXPERIMENTALS=authzen`), and are pinned by `tests/test_findings.py` and `tests/test_common.py`.

| # | Spec claim | Result | Evidence |
|---|---|---|---|
| F1 | OpenFGA returns an error, not a deny, when a condition parameter is missing (§7, review 2 finding 3) | **Verified.** HTTP 400 `validation_error`, "tuple '…' is missing context parameters '[resource_owner]'". Without the always-pass rule, missing and legacy tasks would give 503. With the shim, both give `decision: false` (golden `get-missing`, `get-legacy-no-owner`; smoke: 404 end to end). | `test_openfga_missing_condition_parameter_is_an_error` |
| F2 | `subject.id` is not in OpenFGA's condition context, only `subject_*` properties (§7) | **Verified.** A request with `subject.id` but without `properties.id` fails with "missing … '[subject_id]'". | `test_openfga_subject_id_is_not_in_condition_context` |
| F3 | OpenFGA ID pattern/length limits **[unverified]**; "the shim hashes long IDs" (§7) | **Verified, and stricter than the spec assumes.** Subject IDs must match `^[^:#@\s]{1,500}$` and resource IDs `^[^:#@\s]{1,256}$`. Length isn't the main problem: every `<iss>\|<sub>` owner (has `:`) and every LS Login `sub` (`…@lifescience-ri.eu`, has `@`) is rejected. The shim must hash or encode every subject ID, not only long ones. Ours hashes all of them and passes the real ID as `subject_id`. **Spec text to change:** "the shim hashes long IDs" → "the shim encodes every subject ID (OpenFGA rejects `:`, `#`, `@`, whitespace)". | `test_openfga_identifier_limits` (6 cases), boundaries at 500/256 |
| F4 | Prefix tests need expansion in engines without quantifiers; reference prefixes must end in a delimiter, or expansion and `startswith` disagree (§7) | **Verified.** Expansion equals `startswith` for `:`-terminated prefixes on every golden entitlement set; `urn:g:vo` vs `urn:g:vo2#x` disagrees. **Addition:** OpenFGA's CEL conditions support `exists`/`all` and `startsWith`, so OpenFGA needs no expansion and tests prefixes natively, but only within its CEL cost budget: with the default `OPENFGA_MAX_CONDITION_EVALUATION_COST`, a condition over more than about 5 entitlements or executors fails with HTTP 400 ("cost limit exceeded"), so ordinary LS Login users with dozens of entitlements would get 503 (measured in the service review; the result also depends on list order, because `exists` short-circuits). Compose raises the budget to 100000, the shim caps lists at `SHIM_MAX_LIST_ITEMS` (1024; above that it answers 502), and golden cases at 1024 items pin it. The cost grows with list length × configured values and prefixes × string length (the round-2 review saw 8 VOs fail at 1024 entitlements). So the setup job runs a self-check: worst-case requests at `SHIM_MAX_LIST_ITEMS` items of 200 characters for every configured service. It exits non-zero, so the shim doesn't start, if OpenFGA errors. Checked: with a budget of 2000, setup fails with "actual cost limit exceeded". Separately, OpenFGA's gRPC gateway rejects requests over about 602 KiB, so the OpenFGA shim accepts at most 512 KiB (`SHIM_MAX_BODY_BYTES`). Expansion stays in `common` for Cedar and Casbin. | `test_prefix_expansion_*`; the OpenFGA model's `entitled` condition |
| F5 | In OpenFGA's AuthZEN, `action.name` must be a relation (§7) | **Verified.** An unknown action gives 400 (it would be a 503 at the TES). The shim validates action names first and denies. | `test_openfga_unknown_relation_is_an_error` |
| F6 | Native AuthZEN PDPs return only `decision` (§3.5) | **Verified** for OpenFGA: the body is exactly `{"decision": …}`. | `test_openfga_answers_decision_only` |
| F7 | `tes_task_set:own/all` work natively in OpenFGA with `user:*` tuples; `tes_task` needs the `tes_service` rewrite with a conditioned `user:*` tuple (§7) | **Verified** by the full golden replay. Design note: OpenFGA allows only one tuple per (object, relation, user), so owner and admin need separate relations (`owner`, `admin`, with `GetTask: owner or admin`). | `test_golden_decision[openfga-*]` |
| F8 | OPA needs a ~50-line shim (§7) | **Verified.** The front is ~60 lines with docstrings. The Rego policy also enforces the contract, so OPA called directly (Data API) gives the same 65 decisions. | `test_golden_decision[opa-data-api-*]` |
| F9 | OpenFGA's AuthZEN endpoint is store-scoped, so v1 config takes the full URL (§2, §7) | **Verified**: `/stores/{id}/access/v1/evaluation`. The shim hides this, so the TES config holds the shim URL. | `fga_eval` fixture |
| F10 | `X-Request-ID` (AuthZEN §10.1.3) | OpenFGA **doesn't echo** a client-supplied ID; both shims do, for log correlation. | `test_openfga_does_not_echo_request_id`, `test_shims_echo_request_id` |

| F11 | (not in the spec) shim robustness | Lone UTF-16 surrogates are denied by the contract check (Go would map them to U+FFFD, so distinct IDs could compare equal in OPA); identifiers with a trailing newline are hashed; requests without `Content-Length` get 411; a socket read idle for 5 s drops the client. Total request time and the number of connections aren't bounded by the shims; the mesh in front of them must do that. Empty prefixes in the policy data are rejected at setup, because `"".startsWith("")` would let the shim's empty-image sentinel pass. | `test_shims_deny_lone_surrogates`, `test_shims_deny_service_id_with_newline`, `test_shims_require_content_length`, `test_openfga_shim_rejects_lists_over_limit` |

Not checked here: Cedar entity tags, Cerbos role mapping and Topaz directory behaviour (not in phase 1); OpenFGA Search paging (Search isn't used); Passport validation.

Observation for the policy (no spec change needed): under the reference policy, owners read and cancel their own tasks without a current entitlement, as §7 says. When the claim rule is set, it blocks such users before the PDP is asked (AND, Q10). In a PDP-only deployment, a user who has lost the entitlement keeps access to their old tasks. If that's unwanted, add `member` to the owner branch.

## What phase 2 needs

- **Mock OIDC issuer:** done (`oidc/`, compose service `oidc`; see [Add a TES](#add-a-tes-phase-2)). Every adapter still needs its `token()` and OIDC wiring.
- **Adapters** for Poiesis (kind), TESK (kind), Funnel and TESP (compose), each mapping `HookConfig` onto its configuration keys (spec §4.2).
- **Cases the mock TES can't exercise:** 1 and 22 per TES; 13b (scope-bound cursor, TESK 400); 23 (startup refusal); 24 (Funnel over gRPC, with grpcurl or a Go test). Add them to `tests/conformance/` gated on adapter `features`, and give case 22 a per-TES expectation (today it runs for `mock` only). The userinfo cases 6b, 20 and 21 are in the suite and run for every adapter with the `userinfo` feature.
- **More golden requests from each TES** in `tes-authz/golden/<tes>/`, like Poiesis's: each needs a `reference_policy` expectation (in the wrapper or in `golden/expectations.json`), its service ID in the policy's `services`, and placeholders for owner and issuer values.
- **A home and CI:** done: this repository; the `Integration` job of the `CI` workflow runs `make test` (Docker, about 5 images).
- **Further engines when needed:** Cedar and Casbin (they use `expand_prefixes`), Cerbos and Topaz (whose behaviour is still unverified).

## Contributing

Contributions are welcome! See the organisation's [contributing
guide][contributing] and mind our [code of conduct][code-of-conduct]. Install
the dependencies with `uv sync` and the commit hooks with `uv run pre-commit
install`; `make lint`, `make unit` and `make test` run the checks of CI.

## License

[Apache License 2.0](LICENSE), copyright ELIXIR On-Cloud.

[badge-build-status]: <https://github.com/elixir-cloud-aai/tes-authz/actions/workflows/ci.yml/badge.svg?branch=dev>
[badge-license]: <https://img.shields.io/badge/license-Apache%202.0-blue.svg>
[badge-url-build-status]: <https://github.com/elixir-cloud-aai/tes-authz/actions/workflows/ci.yml?query=branch%3Adev>
[badge-url-license]: <https://www.apache.org/licenses/LICENSE-2.0>
[code-of-conduct]: <https://github.com/elixir-cloud-aai/.github/blob/main/CODE_OF_CONDUCT.md>
[contributing]: <https://github.com/elixir-cloud-aai/.github/blob/main/CONTRIBUTING.md>

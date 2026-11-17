# Testing

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

## Where golden requests come from

`tes-authz/golden/` didn't exist when this was built, so `scripts/gen_golden.py` writes the spec's conformance cases as golden requests into `golden/requests/`. The harness also reads every JSON file under `../golden/` (or the directories in `TES_AUTHZ_GOLDEN_DIRS`). Since then, the Poiesis hook tests have written 6 requests to `../golden/poiesis/`; they're replayed too, and agree with both engines. They use Poiesis's service ID `org.ga4gh.poiesis`, which is therefore in the policy's `services`. It accepts two formats:

- the wrapper `{"name", "case", "description", "request", "expect": {"reference_policy": {"decision": bool}}}`;
- a bare AuthZEN request, whose expectation goes into `golden/expectations.json` under `{"<label>/<file stem>": {"reference_policy": {"decision": bool}}}`, where the label is the directory relative to `tes-authz/` (e.g. `golden`). A non-boolean `decision` or two files with the same name fail loading.

`test_every_golden_case_has_an_expectation` fails for files without one, so a new golden request can't go unchecked. Hook-side golden files (`golden/hook/`) use placeholders such as `{{subject_id}}`, `{{iss}}` and `{{client_id}}`, which each TES adapter fills in.

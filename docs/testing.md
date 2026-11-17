# Testing

| Layer (spec [§8.1](specification.md#81-layers)) | File | What | Phase-1 result |
|---|---|---|---|
| unit | `tests/test_common.py` | URL stripping (36 golden rows of the rule of spec [§3.3](specification.md#33-resources), steps 0 to 6 with 2b and 4b), prefix expansion vs `startswith`, validation, OpenFGA mapping | 54 pass |
| golden | `tests/test_golden.py` | golden files match the generator, every case has an expectation, allowed cases follow the profile, which directories the harness reads (defaults, `TES_AUTHZ_GOLDEN_DIRS`, skipped and rejected directories), Poiesis's URL stripping cases equal `golden/url-stripping.json` | 10 pass |
| 2: engine conformance | `tests/test_engines.py` | 75 golden requests (69 generated + 6 recorded by Poiesis in `golden/poiesis/`) × {OPA via front, OPA Data API, OpenFGA via shim} | 225 pass |
| findings | `tests/test_findings.py`, `test_openfga_model.py` | engine behaviours the spec marked unverified (below), shim hardening | 22 pass |
| 1: hook conformance | `tests/conformance/test_hook.py` | spec cases 2, 4b, 5, 5b, 5c, 5d, 7, 7b, 8, 9, 10, 10b, 11, 11b, 11c (cancel parity), 12, 13, 14, 15 (×5 failure kinds on create, plus get, cancel and list), 16, 17, 18, 19, 22, and the exact request shape of [§3.7](specification.md#37-exact-request-shape), against the stub; userinfo cases 6b, 20 (×5: `sub` mismatch, 500, dropped connection, timeout, `application/jwt`) and 21 for adapters with the `userinfo` feature | 41 pass (mock TES) |
| 3: smoke | `tests/conformance/test_smoke.py` | TES × {OPA, OpenFGA}: allow, deny, foreign get 404, missing get and cancel 404, list scopes | 2 pass (mock TES) |
| OIDC: issuer | `tests/test_oidc_issuer.py`, `tests/test_oidc_jose.py` | the mock issuer itself (in-process, plus one check of the compose service): discovery per host name, JWKS, rotation and retirement, opaque tokens, userinfo modes and failures, control API validation; RS256 cross-checked with PyJWT + `cryptography` in both directions | 73 pass |
| OIDC: mock TES AuthN | `tests/conformance/test_mock_oidc.py` | the mock TES refuses `alg: none`, unpublished keys, wrong audience, expired tokens, another issuer, forged `iss`, unknown `kid`, opaque tokens; accepts tokens after a rotation (JWKS refetch); stamps `<iss>\|<sub>` owners when pinned to both issuers; no or unreachable issuer, wrong userinfo content type, userinfo cache TTL, LRU size and token expiry | 14 pass |
| stack | `tests/test_stack.py` | per-worktree project and port block: defaults, base and overrides, project name check, the exports script, compose uses every port variable | 9 pass |

Total: 451 passed (`make test` in a fresh clone, 2026-11-17, OPA 1.22.4, OpenFGA v1.22.1).

The golden requests cover spec cases 3, 4, 4b, 5, 5d, 6, 7, 9–14 and 17, plus contract checks: missing or wrong profile, unknown service, wrong subject type, unknown set or action. They also cover legacy tasks without an owner, issuer-qualified (`<iss>|<sub>`) and 600-character subject IDs, and task IDs containing `:#@`. Realistic sizes: 1024 entitlements with the match last, 1023 non-matching ones, 1024 executors (all allowed, or the last denied). Malformed projections (executors as object, string or null; entries without image; no task) are denied when an image allowlist is set.

## Where golden requests come from

The harness reads golden requests from three places:

- `golden/requests/`: `scripts/gen_golden.py` writes the spec's conformance cases there (`make golden`).
- `golden/<tes>/`: requests a TES recorded in its own hook tests, every subdirectory of `golden/` except `requests/`, `hook/` and hidden ones (a new non-TES directory under `golden/` must be added to `NOT_RECORDINGS` in `harness/golden.py`). The Poiesis hook tests recorded 6 requests and the URL stripping cases in `golden/poiesis/` (see its `README.md`); they're replayed too, and agree with both engines.
- `TES_AUTHZ_GOLDEN_DIRS`: more directories (`:`-separated) with recordings kept outside this repository, read in addition to the two above (it no longer replaces them). Relative paths are relative to the current directory. A directory that does not exist is skipped with a warning; one that contains a directory already read, such as `golden/` itself, is an error. To replay fresh recordings of a TES that has a `golden/<tes>/` directory here, update that directory rather than adding the fresh copy, which would be replayed next to the committed one.

The Poiesis recordings use Poiesis's service ID `org.ga4gh.poiesis`, which is therefore in the policy's `services`. The harness accepts two formats:

- the wrapper `{"name", "case", "description", "request", "expect": {"reference_policy": {"decision": bool}}}`;
- a bare AuthZEN request, whose expectation goes into `golden/expectations.json` under `{"<label>/<file stem>": {"reference_policy": {"decision": bool}}}`, where the label is the directory relative to the repository root (e.g. `golden/poiesis`), or its absolute path without the leading `/` for a directory outside the repository. A non-boolean `decision` or two files with the same name fail loading.

`test_every_golden_case_has_an_expectation` fails for files without one, so a new golden request can't go unchecked. Hook-side golden files (`golden/hook/`) use placeholders such as `{{subject_id}}`, `{{iss}}` and `{{client_id}}`, which each TES adapter fills in.

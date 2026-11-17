# Poiesis golden requests (layer 1)

Recorded by Poiesis's hook conformance tests (`tests/unit/test_authz.py` on
branch `feat/113-authz-contract`, copies of `tests/unit/golden/authz/*.json`).
Wrapper format of `docs/testing.md` ("Where golden requests come from");
subject identity as placeholders (`{{subject_id}}`, `{{iss}}`, `{{sub}}`,
`{{client_id}}`). The harness replays them against every engine
(`tests/test_engines.py`).

- `context.tes.service_id` is Poiesis's service-info id, `org.ga4gh.poiesis`.
  The `expect.reference_policy` decisions assume that id is in the
  `services` of `config/reference-policy.json`, which it is.
- `create.json` is the request of `golden/hook/create.json` with
  Poiesis's `service_id` and a literal `scope`, plus metadata: Poiesis
  sends exactly the request the engine side expects for its `submit` body.
- Shape choices (spec §3.7): a missing task is sent as `tes_task` with
  `"properties": {}`; task sets carry no `properties` for `ListTasks`;
  `action.properties` is always present (`{}` when empty).
- Owners of other users' tasks are literal (`bob`).
- `url-stripping.json`: the URL stripping rule of spec §3.3, 36 rows,
  identical to `golden/url-stripping.json` (`tests/test_golden.py` checks
  this). Rows marked "spec step 0", "2b" or "4b" test the rules for tab and
  newline characters, backslashes and empty hosts.

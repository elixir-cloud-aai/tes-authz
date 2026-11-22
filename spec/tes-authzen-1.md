# `tes-authzen/1`: bring-your-own authorization for GA4GH TES

> **Draft.** This is **draft 3** of the `tes-authzen/1` profile, accepted for implementation on 2026-11-16, after two review rounds (decisions in §10; draft 3 applies the findings of the review of draft 2), with the changes after acceptance listed below. It may still change before a first release; the profile version on the wire (`context.tes.profile`, §3.4) changes with every incompatible revision.

Basis for the AuthZ work in Poiesis ([JaeAeich/poiesis#113](https://github.com/JaeAeich/poiesis/issues/113)), then TESK (elixir-cloud-aai/tesk-api), Funnel (calypr/funnel) and TESP (CESNET/tesp-api).

Code read: Poiesis dev `14040b1`, tesk-api dev `16c3e90`, Funnel `738ab75`, TESP `3d470f7`.

Changes after acceptance (2026-11-16, verified facts from the phase-1 engine work in this repository's reference tooling, see its Findings page; OPA 1.22.4 and OpenFGA v1.22.1):

1. §7 OpenFGA: OpenFGA rejects every ID containing `:`, `#`, `@` or whitespace (subjects `^[^:#@\s]{1,500}$`, objects `{1,256}`), so the shim encodes every subject ID, not only long ones (findings F3); the missing-parameter error and `subject_id` facts are now verified (F1, F2).
2. §7 OpenFGA: the default CEL cost budget fails conditions over about 5 entitlements or executors; the reference deployment raises `OPENFGA_MAX_CONDITION_EVALUATION_COST`, the shim caps lists at 1024 items (502 above) and bodies at 512 KiB, because OpenFGA's gRPC gateway rejects requests over about 602 KiB (F4).
3. §7: OpenFGA's CEL has `exists` and `startsWith`, so OpenFGA needs no prefix expansion; expansion stays for Cedar and Casbin (F4).
4. §7: the OPA front is about 60 lines (F8).
5. §11: new open question Q11 (owner access after losing the entitlement).

From the Poiesis implementation (2026-11-16):

6. §4.1, §6: a cancel on a missing task asks `GetTask` too, like a denied cancel on a foreign task, so both cost the same calls.
7. §6 Poiesis: `principal_claim` keeps its current lookup; exact-name-first applies only to `lookup` (claim rule and allowlist), since changing `_walk_claim_path` would silently change owners in existing deployments.
8. §3.3: URL stripping fixed (`://` only after a valid RFC 3986 scheme; ambiguous authorities omitted); corrected steps and more golden examples.
9. §3.7 (new): the exact request shape (empty `properties` for missing tasks, `action.properties` always present, no properties on list sets, a new `X-Request-ID` per evaluation); §4.2: list-valued settings are JSON arrays in env vars, `required_scopes` stays CSV.
10. §4.2: extra fail-safe startup checks (SHOULD for all implementations).
11. §3.3: step 2b omits values with a backslash between `://` and the first `/` (WHATWG parsers and urllib3 end the host at `\`, so stripping to the text after `@` would fake the host); two golden rows; step 5 keeps fragments. A review of the Poiesis implementation fuzzed 500,000 strings against urllib3 with the full rule: no host mismatch, no leftover userinfo.
12. §3.6, §4.2: discovery, JWKS and userinfo calls SHOULD be bounded by one timeout, `auth.oidc.timeout` (seconds, default 10, Poiesis's current hard-coded value, so unset changes nothing); case 20's timeout variant uses it, and its `sub`-mismatch variant is not applicable to opaque-token TESes (TESK).
13. §3.3: step 2c (now step 4b, see 15) omits values with an empty authority (`:///`) and an `@` in the rest before `?`/`#` (WHATWG skips the extra slashes, so `https:///u:p@h/p` sends credentials `u:p` to `h`); found while implementing the TESP hook. Three golden rows; the shared golden file has 31 rows.
14. §3.3: step 0 omits any value containing TAB, LF or CR (WHATWG deletes them before parsing, so `https://<TAB>/u:p@h/p` slipped past the empty-authority check and leaked `u:p`); found in the review of the TESP hook. Three golden rows; the shared golden file has 34 rows.
15. §3.3: the empty-authority check moves after userinfo stripping as step 4b (empty host after step 3, `@` in the path), so `https://x@/u:p@h/p` and `https://@/u:p@h/p` no longer turn into the leaking form `https:///u:p@h/p`; found in the review of the Poiesis implementation. Two golden rows; the shared golden file has 36 rows.
16. §3.6, §4.2 (from the TESK hook): the userinfo cache is a SHOULD; TESK keeps its uncached per-request lookup (revocation takes effect at the next request, as its docs promise), and case 21 runs only for adapters declaring `userinfo-cache`. TESK's built-in model keeps owner = creator `sub` (single issuer, §3.1); only the decision-service path uses `<iss>|<sub>`. New TESK-only key `tesk.api.authz.issuer`.
17. §7, §11: Q11 decided (2026-11-16, option b): owners need membership. The reference policy's owner branch is `member and owner == subject.id` (OPA) and `(owner and member) or admin` (OpenFGA), so a PDP-only deployment ends owner access when the entitlement is revoked (for API keys under `/2`, only when the key expires; see §12); golden rows for owners without entitlement (get, cancel, near miss). Reference policy only; no TES hook or contract change.

From the Poiesis implementation (2026-11-22):

18. §12 (new): profile `tes-authzen/2`, a compatible extension of `/1` (subject `via`, `credential_id`, `actor`, `key_age`, `snapshot_age`; task `groups`; TES-specific resource types; an optional response `context.tes`). The reference decision service accepts `/1` and `/2`; its policy gives delegated tokens no admin powers.
19. §3.3, §3.5, §7, §12 (2026-11-22, wording only): the reference policy's "no admin with an `actor`" holds under every profile, as implemented and pinned by the golden rows, not only under `/2`; §12 says it also holds under `/1` and with `actor: null`, and names the three response additions that change what a TES does (`scope`, `groups`, `obligations`); §3.3 and §3.5 point to §12; the operator guide's upgrade note names the newly reserved `FGA_CLAIMS` parameter `delegated`.

Changes since draft 2:

1. The claim rule looks its claim up on its own (exact name, then dotted path; token first, then userinfo), independent of the PDP allowlist; new case for a rule-only setup.
2. TESK gets a new AND-gate key; its existing OR-style `authorisation.claim` stays part of its built-in model.
3. The OpenFGA shim always passes `resource_owner` and `subject_id`, so missing and legacy tasks give 404, not 503.
4. URL stripping is a plain string algorithm with golden cases per branch.
5. Service clients and proTES: leave the rule unset and express them in the PDP (documented, case added); smaller fixes (TESK subject gaps, shim delimiters, probe load, trims).

Changes in draft 2 (since draft 1):

1. One resolved claim view (token ∪ userinfo, token wins) for both the PDP and the claim rule, so TESK (userinfo-only AuthN) is equivalent.
2. Contract leaks closed: URLs in the create projection are stripped of credentials, task IDs must be server-assigned, get/cancel always call the PDP (no 404/503 existence oracle), and an issuer-qualified owner format is fixed.
3. Engine fit corrected: OpenFGA needs a thin shim for task ownership; Cerbos and Topaz are marked unverified; a generic prefix-expansion step makes the reference policy expressible in Cedar and Casbin.
4. Implementation notes corrected (TESK pages, legacy owners, state; Funnel gRPC, `TaskAccess`, worker paths; TESP migration); transport checks moved to a warning (mesh's job).
5. Smaller v1 test plan; profile version on the wire; delivery reordered (userinfo PR first, #113 re-scoped first).

Marker: **[profile]** marks every point where this spec goes beyond what a cited standard says. Everything else is plain AuthZEN 1.0 or plain OIDC. **[unverified]** marks claims not checked against running software.

## 0. Summary

A TES keeps three things: authentication (OIDC), an owner stamped on every task, and a thin hook that asks one question per request. The question is a standard OpenID AuthZEN 1.0 Access Evaluation (`POST /access/v1/evaluation`). Listing uses two evaluations on two fixed "task sets" (`all`, `own`), so that any AuthZEN PDP can answer with plain allow/deny and the TES filters in its own store query. Everything that is policy (entitlements, per-action rules, Passport visas) lives in an external decision service of the operator's choice. A built-in, off-by-default claim rule gives a one-claim admission gate without extra components. Without configuration, every TES behaves as today.

## 1. Scope and non-goals

| Layer | Does | Doesn't |
|---|---|---|
| Mesh / gateway (Envoy, Istio, ingress) | TLS/mTLS between TES and PDP, rate limits, IP rules, endpoint-level rules (e.g. `/service-info` open), optional coarse `ext_authz` | know task owners, filter lists |
| TES (thin hook) | validate the OIDC access token (issuer, audience, existing `required_scopes`); optional userinfo lookup (identity resolution, §3.6); stamp the owner on create; built-in claim rule; one AuthZEN call per decision; turn the list answer into a store filter; fail closed | interpret entitlements, groups, visas, image allowlists, roles |
| Decision service (PDP) | all policy: which entitlements count, per-action rules, admin roles, image or resource limits, Passport/visa validation, token exchange | see the access token; read the TES store |

AuthN is tied to OIDC; AuthZ is agnostic. Reasons: Poiesis accepts only OIDC tokens already, and GA4GH AAI is OIDC-based, with Passports released at userinfo (`ga4gh_passport_v1`).

Non-goals:

- Forwarding the access token to the PDP. At most a later, explicit opt-in (e.g. token exchange). Not in v1.
- Non-OIDC identity sources in v1. The subject stays abstract (`id` plus `iss`, `sub` and claims as properties), so a trusted proxy, mTLS identity or Funnel's Basic users can feed it later without a contract change.
- What a task may do on the cluster (namespaces, quotas, network).
- Sharing lists by group (`owners in [...]`) in v1 (Q2); decision caching in the TES (Q6); write or event calls to the PDP (Q5).
- Worker-side and non-TES RPCs (Funnel events, scheduler, execution claims): untouched.

Known limit: behind proTES (PTF), the TES sees proTES as the caller. proTES stays the enforcement point; the TES trusts proTES only.

## 2. Standards considered

| Option | Verdict | Why |
|---|---|---|
| **OpenID AuthZEN Authorization API 1.0** (Final, approved 2026-01-12; https://openid.net/specs/authorization-api-1_0-final.html, https://openid.net/authorization-api-1-0-final-specification-approved/) | **Pick** (Access Evaluation, §6) | Vendor-neutral JSON over HTTPS; subject/action/resource/context with free `properties`; deny is `200 {"decision": false}`; free-form type and action vocabularies. Final specs aren't revised. |
| AuthZEN Access Evaluations (batch, §7) | Optional, not in the hook | Optional for PDPs; the hook needs at most two calls (Q4). |
| AuthZEN Search APIs (§8) | **Reject for list filtering** | Resource Search returns resources the PDP knows; the PDP doesn't hold the task inventory, and its paging can't be merged with TES filters and cursors (OpenFGA's Search ignores paging altogether). |
| AuthZEN metadata (§9) | Optional | v1 config takes the full evaluation URL (also needed for OpenFGA's store-scoped path). |
| Envoy `ext_authz` | Gateway layer only | Checks HTTP request attributes and returns OK/denied plus headers; no stored owners, no list filtering; Envoy-specific. |
| OASIS XACML 3.0 JSON profile | Reject | Heavy, few modern engines. |
| Engine APIs (OPA Data API, Cedar `is_authorized`, OpenFGA Check, Casbin `enforce`) | Reject as contract; use behind shims | Each ties every TES to one engine. |
| Kubernetes SubjectAccessReview, UMA 2.0 | Reject | Kubernetes-only vocabulary; UMA changes the client flow. |
| GA4GH Passports / AAI | Input, not protocol | Visas arrive as subject properties (from userinfo, or via token exchange in the PDP); the PDP validates them. |

## 3. The contract (AuthZEN mapping)

### 3.1 Subject

```json
{"type": "user", "id": "<owner id>",
 "properties": {"iss": "...", "sub": "...", "client_id": "...", "scope": ["..."],
                "claims": {"<allowlisted claim>": "..."}}}
```

- `id`: the string the TES stamps as task owner, so the PDP can compare `subject.id == resource.properties.owner`. A single-issuer TES keeps its existing owner value (no migration): Poiesis `principal_claim` (default `sub`), TESK userinfo `sub`, Funnel token `sub` (or Basic user). **[profile]** A TES that accepts more than one issuer MUST use `<iss>|<sub>` (exactly: issuer string, `|`, subject string; `|` doesn't occur unencoded in an issuer URL, so a reader splits at the first `|`; `sub` may contain `|`, e.g. `auth0|123`). Only `sub`, or `iss`+`sub`, is a safe owner: mutable claims (`email`, `preferred_username`) make ownership hijackable, and the docs must say so.
- `type`: always `user` **[profile]**, also for service clients and for deployments whose `principal_claim` names a group; the PDP tells them apart by `client_id` or claims.
- `properties.iss`, `sub`, `client_id` (`azp` or `client_id` claim), `scope` (as a list): always sent when known (TESK can't fill `client_id` and `scope` for user tokens, §6).
- `properties.claims`: **one resolved claim view** = `{c: lookup(c)}` for each claim `c` named in `authz.decisionService.claims` (default: none). `lookup` (§6) takes the access token and, if userinfo is on, userinfo; when both have a claim, the token value wins. The claim rule uses the same `lookup`, but not the allowlist (§5). This is identity resolution (which value is the user's), not policy: the TES picks no values and interprets none. A TES that can't read the token (TESK validates opaque tokens at userinfo) fills the view from userinfo only and is still equivalent.
- Built only from the validated token and the TES's own userinfo call; never from request headers, query or body. The access token is never sent.

### 3.2 Actions

`action.name` is the TES OpenAPI `operationId` **[profile]**: `CreateTask`, `GetTask`, `ListTasks`, `CancelTask`. `GetServiceInfo` is not checked (open by default in all four; TESK can close it with `tesk.api.service-info.public=false`, which stays as is). `GetTask`/`ListTasks` carry `action.properties.view` (`MINIMAL`/`BASIC`/`FULL`).

### 3.3 Resources

Two types **[profile]** (`tes-authzen/2` adds task `groups` and TES-specific types, §12):

- `tes_task`: a stored task. `id` = task ID. `properties`: `owner`, `state`, `tags`. Used for `GetTask` and `CancelTask`. `owner` is omitted when the TES has no exact owner (TESK legacy tasks, §6); the reference policy treats a missing owner as "not the caller's".
- `tes_task_set`: a set of tasks; `id` is `own` or `all`. Used for `CreateTask` (`own`: the new task joins the caller's set; AuthZEN requires an `id`, and no TES knows the new task's ID portably before the decision) and `ListTasks` (§3.5).

On `CreateTask`, `properties.task` is a fixed projection of the submitted task: `name`, `tags`, `resources` (`cpu_cores`, `ram_gb`, `disk_gb`, `preemptible`, `zones`; not `backend_parameters`, whose keys are arbitrary and may hold secrets), `volumes`, `executors[].image`, `inputs[].{url,path,type}`, `outputs[].{url,path,type}`. URLs lose userinfo (`user:pass@`), query (presigned signatures, SAS tokens) and fragment by a plain string algorithm, not a URL library (Python, Java and Go parsers disagree on `s3://`, `drs://`, `file:///`, IPv6 and malformed input, and a fallback to the raw value would leak) **[profile]**:

- **Step 0, tab and newline:** if the value contains TAB, LF or CR anywhere, omit the field. WHATWG parsers delete these characters before parsing, so `https://<TAB>/u:p@h/p` connects to `h` with credentials `u:p`.
- **Step 1, scheme:** if the value starts with a scheme per RFC 3986 (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`) immediately followed by `://`, split it into `scheme://`, the region W (from after `://` to the first `/`, or the end) and the rest. Otherwise go to step 5. A `://` anywhere else is not a separator.
- **Step 2, ambiguity:** if W contains `@` and its last `@` comes after the first `?` or `#` in W, omit the field. (Userinfo with an unencoded `?`/`#`, or a query with `@` before any `/`; guessing either way leaks credentials or lets a client fake the host.)
- **Step 2b, backslash:** if W contains `\`, omit the field. WHATWG URL parsers and urllib3 end the host at `\`, so `https://evil.example\@trusted.example/p` connects to `evil.example`, while step 3 would report `trusted.example`.
- **Step 3, authority:** the authority A is W up to its first `?` or `#`; the remainder of W joins the rest. If A contains `@`, drop everything up to and including its last `@`.
- **Step 4, query and fragment:** cut the rest at its first `?` or `#`. The result is `scheme://` + A + rest. `@` in the path (after the first `/`) is kept.
- **Step 4b, empty host:** if the authority left after step 3 is empty and the path (after step 4) contains `@`, omit the field. WHATWG parsers skip the extra slashes for special schemes, so `https:///u:p@h/p`, `https://x@/u:p@h/p` and `https://@/u:p@h/p` connect to `h` with credentials `u:p`. This also omits values such as `file:///d/user@x/f`; omitting only loses audit detail, never leaks.
- **Step 5, no scheme:** keep the value unchanged if it contains neither `@` nor `?`; otherwise omit the field. A fragment (`#…`) is kept here: step 5 doesn't cut it.
- **Step 6:** no other normalisation (case, percent-encoding, ports stay as sent).

Golden cases, one or more per branch (a review of the Poiesis implementation fuzzed 500,000 strings against urllib3 with the full rule and found no host mismatch and no leftover userinfo):

| Input | Output |
|---|---|
| `https://u:p@h/p?sig=x` | `https://h/p` |
| `s3://b/k?X-Amz-Signature=x` | `s3://b/k` |
| `drs://u:p@h/obj` | `drs://h/obj` |
| `ftp://a@b@h/p` | `ftp://h/p` |
| `https://h?sig=x` | `https://h` |
| `https://h/p#frag` | `https://h/p` |
| `s3://b/user@x/f` | unchanged |
| `file:///d/f` | unchanged |
| `https://u:p?ss@h/p` | omitted (step 2) |
| `https://evil?x=@trusted/p` | omitted (step 2) |
| `https://evil.example\@trusted.example/p?x=1` | omitted (step 2b) |
| `https://u:p@h\x@y/p` | omitted (step 2b) |
| `https:///u:p@h/p` | omitted (step 4b) |
| `file:///d/user@x/f` | omitted (step 4b) |
| `file:///d/f?x=@y` | `file:///d/f` |
| `https://x@/u:p@h/p` | omitted (step 4b) |
| `https://@/u:p@h/p` | omitted (step 4b) |
| `https://<TAB>/u:p@h/p` | omitted (step 0) |
| `https://u:p@h<LF>/p` | omitted (step 0) |
| `/local/a<CR><LF>b` | omitted (step 0) |
| `/local/file#1` | unchanged (step 5 keeps fragments) |
| `u:p@host/x://y` | omitted (no scheme before `://`; contains `@`) |
| `1s://u@h/p` | omitted (invalid scheme; contains `@`) |
| `/local/path` | unchanged |
| `/local/path?x` | omitted |
| `user@host:path` | omitted |

Never `executors[].command`, `env`, or `inputs[].content`. Client-supplied values (tags such as TESK's `GROUP_NAME`) are claims by the client, not facts.

Prerequisite **[profile]**: the TES assigns task IDs itself and ignores client-supplied `id`, `state`, `creation_time` and logs. Otherwise a client could create with someone else's ID and learn of its existence from the conflict. Status: Funnel overwrites them (`InitTaskWithForbiddenPathPrefixes(task, true, …)`); TESP ignores a client `id` (server-generated ID, `exclude={"id"}` on insert; verified in review); Poiesis does not (`task.id = task.id or str(uuid.uuid4())` in `routes/tasks.py`), to be fixed with or before PR 1; TESK names jobs itself **[unverified]**.

Get/cancel send only owner, state and tags because the hook must read the task before deciding, one store read per call. In Poiesis, Funnel and TESP that's one indexed lookup by ID. In TESK, owner and tags are job metadata but `state` is derived from executor jobs and pods; GET already reads all of that, so the cost is already paid. Image or resource rules belong at admission (`CreateTask`).

### 3.4 Context

`context.tes`: `{"profile": "tes-authzen/1", "service_id": "<service-info id>"}` **[profile]**. `profile` versions the vocabulary (set IDs, projection fields, owner format), so later changes don't silently change what PDPs receive. `tes-authzen/2` (§12) is the current extension. The TES sends a server-generated `X-Request-ID` (AuthZEN §10.1.3), new for each evaluation (§3.7), never a client-supplied value; trace propagation follows the TES's existing tracing, if any.

### 3.5 List filtering

`ListTasks` asks two plain evaluations, `ListTasks` on `tes_task_set:all` and on `tes_task_set:own` (in parallel, or `all` first):

| `all` | `own` | TES does |
|---|---|---|
| true | any | list without owner filter |
| false | true | list with `owner = subject.id` |
| false | false | 403 |

The scope becomes a predicate in the TES's own query, applied with the user's filters and cursor: pages are correct and complete (no duplicates, no gaps, no foreign tasks), with size ≤ `page_size` (TESK already returns short pages, since it filters names, tags and state after reading a page of jobs). The scope is re-evaluated on every page. A TES whose cursor depends on the predicate (TESK: Kubernetes continue tokens belong to the original label selector) MUST bind the page token to the scope and answer a mismatch with 400 **[profile]**; keyset cursors (Poiesis, Funnel, TESP) need nothing.

Two fixed set IDs instead of a filter in the response `context`, because native AuthZEN PDPs (OpenFGA, Cerbos) return only `decision`. Under `tes-authzen/2` a decision on `own` may carry a `context.tes.scope` that widens the list beyond `owner = subject.id` (§12); the table above (and §6's pseudocode) is the whole rule under `/1` and for plain decisions. A TES that binds its page token to the scope includes that `scope` in what it binds. `ListTasks` with `view=FULL` triggers no per-task evaluations.

### 3.6 Userinfo (identity resolution, in the TES)

Part of AuthN. Off by default (`auth.oidc.userinfo.enabled`). Endpoint from OIDC discovery. The userinfo `sub` MUST equal the token's `sub`, else 401. Bounded LRU cache keyed by a hash of the token, entries kept until min(token `exp`, 5 minutes) to limit revocation lag (SHOULD; a TES whose AuthN already looks up userinfo on every request, such as TESK, MAY keep doing so without a cache, which removes the lag; conformance case 21 then doesn't apply). Discovery, JWKS and userinfo calls SHOULD be bounded by one timeout, `auth.oidc.timeout` (seconds, default 10, the value Poiesis hard-codes today for discovery and JWKS, so unset changes nothing). Error, timeout, or a non-JSON response (signed or encrypted userinfo, `application/jwt`, isn't supported) → 401. TESK already does the lookup as its AuthN. Passports delivered via token exchange (GA4GH AAI) are the PDP's concern.

### 3.7 Exact request shape

So that all four TES produce byte-comparable requests (golden files):

- Every request has `subject`, `action`, `resource` and `context`, as in §3.1–§3.4.
- `action.properties` is always present: `{"view": "<MINIMAL|BASIC|FULL>"}` for `GetTask` and `ListTasks`, `{}` for `CreateTask`, `CancelTask` and the extra `GetTask` on the cancel path (no view is requested there; as implemented in Poiesis).
- `tes_task`: `properties` is `{"owner", "state", "tags"}` for a stored task (`owner` left out when unknown, §3.3), and exactly `{}` for a missing task.
- `tes_task_set`: no `properties` key on `ListTasks` (`all`, `own`); `{"task": <projection>}` on `CreateTask`.
- `subject.properties`: keys with no value are left out (not `null`); `claims` is always present, `{}` when empty.
- `X-Request-ID`: newly generated for each evaluation (two per `ListTasks`, up to two per `CancelTask`), never reused or taken from the client.

Example (`GetTask` on a missing task):

```json
{"subject": {"type": "user", "id": "abc", "properties": {"iss": "https://idp", "sub": "abc", "scope": ["openid"], "claims": {}}},
 "action": {"name": "GetTask", "properties": {"view": "MINIMAL"}},
 "resource": {"type": "tes_task", "id": "0b6c…", "properties": {}},
 "context": {"tes": {"profile": "tes-authzen/1", "service_id": "org.example.tes"}}}
```

## 4. Failure semantics, configuration, security

### 4.1 Failures and status codes

| Situation | Result |
|---|---|
| No or invalid token, userinfo failure | 401 |
| Missing `required_scopes` (Poiesis, existing AuthN check, before the claim rule) | 403 (unchanged) |
| Claim rule fails | 403 on every action, PDP not called |
| PDP deny on CreateTask, ListTasks (both sets) | 403 |
| PDP deny on GetTask | 404 (no existence oracle; today's owner-only behaviour) |
| PDP deny on CancelTask | the hook asks `GetTask` once more: allowed → 403, else 404 |
| Task doesn't exist (GetTask/CancelTask) | the PDP is still called, with `tes_task:<id>` and `"properties": {}`; then 404 whatever it says. CancelTask on a missing task also asks `GetTask`, like a denied cancel on a foreign task. So missing and foreign tasks cost the same calls, and a PDP outage gives 503 for both (no oracle during outages, much smaller timing difference). Exception, accepted: for a caller allowed to cancel everything (an admin), an existing task costs one call and a missing one two; such callers can list all tasks anyway |
| PDP timeout (default 2 s), connection error, non-200, body not JSON, `decision` missing or not boolean | deny; 503 **[profile]** with a generic message; cause logged (D3) |

One attempt, no retries. Anything other than `{"decision": true, ...}` is a deny. Residual: the store read for a missing ID is slightly faster than for an existing one; accepted and documented. Every GET or cancel on a random ID now costs a PDP call, so probing loads the PDP; rate limiting is the mesh's job (§1).

### 4.2 Configuration keys

| Key | Meaning |
|---|---|
| `auth.oidc.userinfo.enabled` | userinfo lookup (§3.6) |
| `auth.oidc.timeout` | seconds, default 10; bounds discovery, JWKS and userinfo calls (§3.6) |
| `authz.requiredClaim.name` | claim for the built-in rule: exact top-level name first (URI-named claims such as `https://example.org/groups`), else a dotted path |
| `authz.requiredClaim.values` | exact values (list) |
| `authz.requiredClaim.prefixes` | raw string prefixes (list) |
| `authz.decisionService.url` | full AuthZEN evaluation URL; unset = built-in owner rule |
| `authz.decisionService.timeout` | seconds, default 2 |
| `authz.decisionService.claims` | claim names in the resolved view (§3.1) |
| `authz.decisionService.credentialFile` | optional file with a bearer credential for TES→PDP (AuthZEN §11.2: the PDP SHOULD authenticate the PEP) |

List-valued settings (`requiredClaim.values`, `requiredClaim.prefixes`, `decisionService.claims`) are JSON arrays when given as environment variables (group URNs can contain commas), e.g. `POIESIS_AUTHZ_REQUIRED_CLAIM_PREFIXES='["urn:geant:lifescience-ri.eu:group:vo:"]'`; config files and Helm values use their native lists. Existing CSV settings (Poiesis `POIESIS_AUTH_OIDC_REQUIRED_SCOPES`) stay CSV. Mapping: Poiesis env `POIESIS_` + upper snake (`POIESIS_AUTHZ_DECISION_SERVICE_URL`), Helm values verbatim. TESK Spring `tesk.api.authz.decision-service.url` (env `TESK_API_AUTHZ_DECISION_SERVICE_URL`) and a new `tesk.api.authz.required-claim.{name,values,prefixes}`, enforced as an AND gate before the SpEL expressions. TESK's existing `tesk.api.authorisation.claim.*` is not reused: it sets `claimAuthorised`, an OR grant that admits users without groups (`isAuthorisedWithoutGroup()`, ORed with group membership in `TesService`'s `@PreAuthorize`), so reusing it would change existing deployments or make TESK's rule an OR. It stays part of TESK's built-in group model. TESK also needs `tesk.api.authz.issuer` (env `TESK_API_AUTHZ_ISSUER`), required with the decision service, because its opaque-token userinfo doesn't name the issuer; it fills `subject.properties.iss` and the `<iss>|<sub>` owner. Funnel YAML `Server.Authz.DecisionService.URL`. TESP Dynaconf `[authz] decision_service.url`, env `TESP_API_AUTHZ__DECISION_SERVICE__URL`. #113 proposed `POIESIS_AUTH_OIDC_REQUIRED_CLAIM*`; the rule moves under `authz` because it decides (note on #113, §9).

Startup checks: `authz.*` set while auth is disabled → refuse to start (no anonymous principal reaches a PDP). `requiredClaim.name` without values and prefixes → refuse to start. Implementations SHOULD also refuse to start on (fail-safe checks from Poiesis): an empty string among `values` or `prefixes` (an empty prefix matches everything); any `authz.decisionService.*` key set without `url`, or a `url` that isn't `http(s)://` with a host; a `credentialFile` that is empty or unreadable. A non-loopback `http://` PDP URL → warning only: AuthZEN §11.1 requires a secured PEP–PDP connection, which a mesh (mTLS sidecar) usually provides; transport is the mesh's job.

### 4.3 Security

- No identity spoofing: the subject comes only from the validated token (issuer and audience pinned) and the TES's own userinfo call; the owner is stamped server-side; client-supplied owner-like fields are ignored; client task IDs are ignored (§3.3).
- No token forwarding (§1).
- Transport: loopback sidecar, mesh mTLS or HTTPS; a NetworkPolicy so only the TES reaches the PDP; the optional PEP credential from a file, never an env var.
- Logs: decision, action, resource ID, request ID; never tokens or claim values.

## 5. Built-in claim rule and composition

Rule: allowed if the claim `lookup(rule.name)` (§6: exact name, then dotted path; token first, then userinfo; with userinfo off, the access token only; independent of the PDP allowlist) is a string or list of strings with a value equal to one of `values` or starting with one of `prefixes`. Prefixes are raw string prefixes: operators include the delimiter. LS Login recipe: the group itself as an exact value (`urn:geant:lifescience-ri.eu:group:vo#<authority>`, authority as released by LS Login) plus `urn:geant:lifescience-ri.eu:group:vo:` as prefix for its subgroups; a prefix without the trailing `:` would also admit `…:group:vo2#…`. Off when `name` is unset. Missing claim or wrong type → deny.

Composition: claim rule AND decision. Order: token (issuer, audience, `required_scopes`) → userinfo (if on) → claim rule → store read (get/cancel) → decision (PDP if configured, else built-in owner rule). Both must allow.

Why AND, not "the PDP replaces the rule" (#113's wording): the rule is an admission gate ("who may use this service"), the PDP decides "what may this user do". With AND, each is meaningful alone, unset is a no-op, an operator who wants PDP-only leaves the rule unset, and a misconfigured PDP can't widen access beyond the gate. Cost: one local comparison.

Consequence: every caller must carry the claim. Client-credentials tokens (service clients, and proTES, which the TES sees as the caller, §1) carry no user entitlements, so they get 403 when the rule is set. Deployments with service clients or behind proTES leave the rule unset and express "entitled users or client X" in the PDP (e.g. by `subject.properties.client_id`). No OR or exemption keys in the TES: that would be policy. The operator docs say so.

Built-in default (no PDP): Poiesis and TESP: today's owner rule (create allowed; get/cancel/list own tasks). Funnel keeps `TaskAccess` (default `All`: with only the claim rule set, every admitted user sees every task; documented), TESK its group model. When a PDP is set, these are ignored and the PDP decides. Equivalence across implementations is required for the claim rule and the PDP path only.

## 6. The hook

```text
lookup(p, name)   = first found of: t[name], u[name], path(t, name), path(u, name)
                    # t = token claims, u = userinfo claims ({} if off); exact name before dotted path;
                    # token before userinfo at each step; path() splits at "." and walks objects
subject(p)        = {type:"user", id:p.owner_id,
                     properties:{iss, sub, client_id, scope,
                                 claims: {c: lookup(p,c) for c in allowlist if found}}}
gate(p)           = if rule.name unset: ok
                    v = lookup(p, rule.name)                      # not filtered by the allowlist
                    if v is string: v = [v]; if v is not a list of strings: raise 403
                    if any(x in rule.values or any(x.startswith(q) for q in rule.prefixes) for x in v): ok
                    else raise 403
ask(p, act, res, aprops={})
                  = POST pdp.url {subject(p), action:{name:act, properties:aprops}, resource:res,
                                  context:{tes:{profile:"tes-authzen/1", service_id}}}
                      timeout, X-Request-ID = server-generated
                    return body.decision is exactly true; on any failure raise 503

CreateTask(p, task):  gate(p); drop client id/state/creation_time/logs
                      if pdp and not ask(p,"CreateTask",{type:"tes_task_set",id:"own",properties:{task:project(task)}}): 403
                      task.owner = p.owner_id; store(task)
GetTask(p, id, view): gate(p); meta = store.read_meta(id)            # no owner filter; may be None
                      allow = pdp ? ask(p,"GetTask",{type:"tes_task",id,properties:meta?{owner,state,tags}:{}},{view})
                                  : meta and meta.owner == p.owner_id
                      if not meta or not allow: 404
CancelTask(p, id):    gate(p); meta = store.read_meta(id)
                      if not pdp: if meta and meta.owner == p.owner_id: proceed else 404
                      allow = ask(p,"CancelTask",res(id,meta))       # res: properties {} if meta is None
                      if meta and allow: proceed
                      g = ask(p,"GetTask",res(id,meta))               # missing or denied: same calls
                      if meta and g: 403 else 404
ListTasks(p, f, view):gate(p)
                      if not pdp: scope = OWN
                      else: a, o = ask(p,"ListTasks",{tes_task_set,"all"},{view}), ask(...,"own",...)
                            scope = a ? ALL : o ? OWN : raise 403
                      store.list(f + (scope==OWN ? owner=p.owner_id : none), cursor bound to scope if needed)
```

**Poiesis** (`poiesis/api/auth.py`, `routes/tasks.py`, `db/tasks.py`, `settings.py`). A new `authz.py` holds `gate`, `ask`, `subject` and the list scope; a FastAPI dependency next to `get_principal` runs the gate. `Principal.claims` already has the validated claims. `principal_claim` keeps its current lookup (`_walk_claim_path`, dotted path only): making it exact-name-first would silently change task owners in existing deployments whose claim names contain dots. Exact-name-first applies only to `lookup` (claim rule and allowlist), a new helper. `get_task(..., principal=None)` (existing internal bypass) gives the unfiltered read, plus a cheap owner/state/tags query. List sets `filters.principal = None` for ALL; keyset cursor unchanged. Also: ignore client task IDs. Hard: little; `principal_claim` may differ from `sub`, so `subject.id` and `properties.sub` can differ.

**TESK** (`config/security/ResourceServerConfiguration.java`, `tes/service/TesService.java`, `TesServiceImpl.java`, `k8s/service/KubernetesClientWrapper.java`, `CreatorLabels`). The decision lives in a Spring bean (`@tesAuthz`) called from the existing `@PreAuthorize`/`@PostAuthorize` SpEL; the bean switches on "PDP set?" because annotations are static. AuthN is userinfo introspection, so the resolved view comes from userinfo only; `User` must keep `iss` and the raw userinfo claims. Subject properties TESK can't fill for user tokens: `client_id` and `scope` (userinfo carries neither); service-client tokens are decoded (`ServiceClientTokenServices`) and fill them. TESK gets its own golden values for these fields, and policies that must work with TESK don't use `scope`/`client_id` to judge users. Missing tasks throw 404 before `@PostAuthorize` runs, so the "call the PDP anyway" path (§4.1) needs explicit code: catch not-found, call `@tesAuthz`, rethrow. List: ALL drops the user label selector, OWN uses the creator hash label; page tokens get a scope prefix (§3.5). Owner = the creator annotation (exact ID, checked against the hash label). Legacy tasks (only `creator-user-id`, lossy `@`→`_`) have no exact owner: `owner` omitted, so only `all`-scope callers reach them under a PDP; operators with legacy tasks keep the built-in model until those tasks expire. The group model (`GROUP_NAME`, managers) stays built-in only.

**Funnel** (`internal/server/auth/auth.go`, `auth_oidc.go`, `internal/identity/identity.go`, `internal/server/taskservice/service.go`, backends in `internal/database/*/tes.go`). The hook covers the four TES RPCs only; it runs in the task service, below the gRPC interceptor, so the gRPC and HTTP-gateway paths both pass it. The interceptor must keep `iss` and the validated claims (today `sub` and the token). List: ALL → `CanSeeAllTasks()` true, OWN → owner filter, no backend change. Get/cancel: owner checks sit inside each backend (`IsAccessible`), so the hook reads with a system identity in the task service only, decides, then proceeds. `IsAccessible` uses in events, reservations and execution claims (worker paths) stay as they are. `TaskAccess` is ignored when a PDP is set. Basic users have no `iss` (abstract subject, `iss` omitted). Hard: the central read-decide wrapper over 6 backends.

**TESP** (`tesp_api/api/endpoints/endpoint_utils.py`, `task_endpoints.py`, `repository/task_repository.py`, `utils/token_validator.py`, `config/properties.py`). The hook relies on pinned issuer(s) and audience (§4.3). With more than one issuer, owners become `<iss>|<sub>`, with a migration that backfills `author = "<pinned iss>|" + author` for existing tasks. Then `parse_verify_token` returns a principal; `author` is the owner; `Maybe(author) = Nothing` already means ALL. Hard: the pymonad `Promise` chains make read-decide-proceed awkward.

## 7. Reference decision service and engines

Reference service: a small AuthZEN PDP (`/access/v1/evaluation` plus `/.well-known/authzen-configuration`) whose behaviour is set by one policy. The reference deployment is one configuration of it:

- CreateTask on `own`: `subject.properties.claims.eduperson_entitlement` contains the group (exact) or a subgroup (prefix `…:vo:`); optional image prefix allowlist on `resource.properties.task.executors[].image`.
- GetTask/CancelTask: a member entitlement and `resource.properties.owner == subject.id`, or an admin entitlement (admin: an admin entitlement and no `actor` key in `subject.properties`, under every profile, §12); missing owner → only admins. Owners need a current entitlement, so revoking it ends their access at once, also without the claim rule (Q11, decided (b)).
- ListTasks: `own` for members; `all` for admins (same admin rule).
- Optional: Passport visas (`ga4gh_passport_v1`) validated here, never in the TES.

Generic shim step, shared by all shims (not policy): **prefix expansion** adds, for each string value of a list-valued claim, the set of its prefixes ending at a delimiter (e.g. `a:b:c#x` → `a:`, `a:b:`, `a:b:c#x`), so engines without quantifiers (Cedar, Casbin) can test "has a subgroup of" with set membership. The delimiter set is a shim setting (default `:`; e.g. `/` for Keycloak group paths). Reference-policy prefixes must end in a delimiter, or Cedar and Casbin will decide differently from OPA's `startswith` (verified on the golden entitlement sets). OPA and OpenFGA test prefixes natively and don't use expansion.

| Engine | How it plugs in | Adapter | Native vs shim |
|---|---|---|---|
| OPA (reference) | Rego reads the AuthZEN request as `input`; a front of about 60 lines (verified) → `POST /v1/data/tes/allow`, or the community `opa-authzen-plugin` | thin | all policy in Rego; `some`/`startswith` native |
| OpenFGA | experimental AuthZEN (`OPENFGA_EXPERIMENTALS=authzen`), store-scoped path `/stores/{id}/access/v1/evaluation` | thin shim for `tes_task` | Evaluation is a Check: `action.name` must be a relation, a Check needs a stored tuple, no object wildcards, no contextual tuples in its AuthZEN binding; properties arrive as `subject_*`/`resource_*` condition context (all per openfga.dev/docs/interacting/authzen). So `tes_task_set:own/all` work natively (fixed objects, group or `user:*` tuples); for `tes_task:<id>` the shim rewrites the object to `tes_service:<service_id>` with a conditioned `user:*` tuple (`resource_owner == subject_id`). OpenFGA returns an error (400), not a deny, when a condition parameter is missing, and `subject.id` isn't in its condition context (only `subject_*` properties are); both verified. So the shim always passes `resource_owner` (empty string when absent: missing or legacy tasks) and `subject_id` in the context; otherwise missing tasks would give 503 instead of 404. IDs (verified): subjects must match `^[^:#@\s]{1,500}$`, objects `^[^:#@\s]{1,256}$`, so every `<iss>|<sub>` owner and every LS Login `sub` (`…@lifescience-ri.eu`) is rejected as is: the shim encodes every subject ID (ours hashes all of them) and passes the real ID as `subject_id`. Prefix tests run natively in CEL (`exists`, `startsWith`), no expansion. CEL cost (verified): with the default `OPENFGA_MAX_CONDITION_EVALUATION_COST`, a condition over more than about 5 entitlements or executors fails with 400, i.e. 503 at the TES for ordinary LS Login users; the reference deployment raises the budget, the shim caps lists at 1024 items (502 above that) and checks the worst case at setup. Body limit: OpenFGA's gRPC gateway rejects requests over about 602 KiB, so the shim accepts at most 512 KiB. Unknown action names give 400 in OpenFGA; the shim validates them first and denies. Alternative: owner tuples written on create (Q5) |
| Cedar | shim maps `subject`→`User::"id"`, `action`→`Action::"GetTask"`, resource → `TesTask::"id"` / `TesTaskSet::"own"`, properties → attributes, claims after prefix expansion → sets | thin | Cedar has no quantifier over sets and `like` on single strings only; the reference policy uses `contains` on expanded prefixes. Arbitrary tag keys need entity tags **[unverified]** |
| Casbin (FOCA) | shim → `enforce(sub, obj, act)` with an ABAC model over properties | thin | prefix test via expanded prefixes or a custom matcher function |
| Cerbos | native AuthZEN endpoint per third-party listings | **[unverified]** | Cerbos principals carry roles; how AuthZEN subjects get roles is unverified. Fallback: a fixed default role plus derived roles from `subject.properties` (policy side), else a thin shim |
| Topaz | native AuthZEN | **[unverified]** | resolves subjects from its own directory; unknown subjects may fail |
| Custom | any HTTP service returning `{"decision": bool}` | none | — |

## 8. Test plan

### 8.1 Layers

1. **Hook conformance** (TES × recording stub PDP): the shared cases against a stub that returns scripted decisions and records requests; asserts behaviour and the request JSON against golden files (owner IDs as a per-TES fixture value, request IDs masked).
2. **Engine conformance** (engine × reference policy, no TES): each engine answers the golden requests; one expected-decision table for all, with the per-engine native/shim split of §7 documented.
3. **Smoke** (TES × engine): one allow and one deny per cell of the full matrix.

Scope (D4): the full TES × engine matrix, in two phases.

- **Phase 1:** Poiesis hook (layer 1); OPA and OpenFGA (layer 2; OpenFGA via its shim for `tes_task`, its expectations include case 11 and a legacy task without owner: deny, not error); smoke for Poiesis × {OPA, OpenFGA}.
- **Phase 2, right after:** TESK, Funnel and TESP hooks against the same harness, unchanged: layer 1 for each, smoke rows × {OPA, OpenFGA}. Funnel and TESP are test-only targets in this phase (the hooks are built and tested against the harness; contributing them upstream is a separate step).
- Cerbos, Topaz, Cedar and Casbin join layer 2 (and the smoke columns) when someone needs them; nothing in the harness changes for them.

### 8.2 Shared conformance cases

Cases 1 and 22 have per-TES expectations (built-in defaults differ, §5); all others are identical.

| # | Given | When | Then |
|---|---|---|---|
| 1 | nothing configured | any TES call | behaviour as today (per TES) |
| 2 | nothing configured | GET service-info, no token | 200 |
| 3 | rule `values=[a]`, claim `a` | CreateTask | 200 |
| 4 | rule `prefixes=[urn:g:vo:]`, claim `urn:g:vo:sub#x` | CreateTask | 200 |
| 4b | rule `prefixes=[urn:g:vo:]`, claim `urn:g:vox#x` | CreateTask | 403 |
| 5 | rule set, claim missing or no match | each of 4 actions | 403, PDP not called |
| 5b | rule set (`values=[a]`), no PDP, empty claims allowlist | CreateTask with claim `a` | 200 (rule doesn't depend on the allowlist) |
| 5c | rule set by dotted path `ctx.groups` / by URI name `https://e.org/groups` | CreateTask with matching claim | 200 |
| 5d | rule set, client-credentials token without the claim | CreateTask | 403 |
| 6 | rule set, claim is a list with one match | CreateTask | 200 |
| 6b | userinfo on, claim only in userinfo / in both with different values | CreateTask with rule and PDP | rule and `properties.claims` use userinfo value / token value |
| 7 | PDP allows | CreateTask | 200; owner = subject.id; request = golden `create` (URLs stripped, no `backend_parameters`, `context.tes.profile`) |
| 7b | PDP allows | CreateTask with client `id`, `state` | server-assigned ID and state |
| 8 | PDP denies | CreateTask | 403, nothing stored |
| 9 | PDP allows | GetTask on another's task | 200 |
| 10 | PDP denies GetTask and CancelTask | GetTask / CancelTask | 404 / 404; task unchanged |
| 10b | PDP allows GetTask, denies CancelTask | CancelTask | 403 |
| 11 | PDP allows or denies | GetTask on missing ID | 404; PDP called with no properties |
| 11b | PDP down | GetTask on missing and on existing ID | 503 for both |
| 11c | PDP denies (or allows) | CancelTask on missing ID | 404; PDP asked `CancelTask`, then `GetTask` if the cancel was denied, both with `"properties": {}` and distinct request IDs |
| 12 | PDP: all=true | ListTasks, 3 pages | every task, complete, no duplicates |
| 13 | PDP: all=false, own=true | ListTasks, pages of 2 | only own tasks, complete, no duplicates, sizes ≤ 2 |
| 13b | scope changes between pages | next page | keyset TES: new scope applied; scope-bound cursor (TESK): 400 |
| 14 | PDP: both false | ListTasks | 403 |
| 15 | PDP times out / 500 / `{"decision":"true"}` / no `decision` | any action | 503, logged, nothing executed |
| 16 | PDP set, rule fails | any | 403, PDP not called |
| 17 | rule passes, PDP denies | CreateTask | 403 |
| 18 | client sends `X-Request-ID`, identity headers, owner-like tags | CreateTask | subject from token only; PDP sees a server-generated request ID |
| 19 | allowlist `[eduperson_entitlement]` | any | `properties.claims` has only that claim; no token anywhere in the request |
| 20 | userinfo on; userinfo `sub` differs (not applicable for opaque-token TESes, i.e. TESK: no token `sub` to compare) / endpoint down / slower than `auth.oidc.timeout` / `application/jwt` | any | 401 |
| 21 | userinfo on, two calls with one token | any ×2 | one userinfo call |
| 22 | built-in default (no PDP) | GetTask on another's task / ListTasks | per TES (Poiesis, TESP: 404 / own only; Funnel: per `TaskAccess`; TESK: group model) |
| 23 | authz set, auth disabled | startup | refuses to start |
| 24 | Funnel only | cases 7, 10, 13 over gRPC | same results as over HTTP |

### 8.3 Harness

- Mock OIDC issuer (discovery, JWKS, userinfo; mints JWTs and accepts opaque tokens at userinfo for TESK).
- Recording stub PDP with a control endpoint for scripted decisions.
- One TES-agnostic pytest suite over HTTP, plus a Go test (or grpcurl) for Funnel's gRPC case; per-TES fixtures (kind for Poiesis and TESK, docker compose for Funnel and TESP).
- Golden requests and the URL-stripping cases live with the suite; layer 2 replays them. Home: this repository (`harness/`, `golden/`), shared by phase 1 and phase 2; each TES's CI pulls it for its layer 1.

## 9. Delivery to Poiesis

Two parts: (a) userinfo support (OIDC identity enrichment, §3.6, plus the resolved claim view), (b) the AuthZ contract (hook, claim rule, PDP call, server-assigned IDs).

- Reviewability: (a) is AuthN-only, about 150 lines in `auth.py`/settings plus tests; (b) touches routes, DB reads and config, a few hundred lines. Apart, each review is focused.
- Useful alone: (a) helps without (b) (claims in `Principal`, Passport-aware setups); (b) works without (a) (token claims only).
- Order: no hard dependency, but (a) first fixes the shape of the resolved claim view that (b)'s golden files use, and it's smaller and uncontroversial. An LS Login setup needs both.
- #113 proposed the interface and claim rule first, the PDP call "with it or later", and an optional userinfo setting. Splitting (b) further would leave #113 partly done per PR; the PDP call is small next to the hook.
- Stall risk: a single PR lets a debate on the PDP contract hold up userinfo.

Recommendation: two PRs. Before either opens, a comment on #113 moves userinfo to a new issue and records the changes against #113: AND composition instead of "PDP decides instead of the rule", keys under `authz.*`, the AuthZEN wire format, server-assigned IDs. PR A (userinfo) closes the new issue, references #113, and lands first. PR B (AuthZ contract) closes #113.

## 10. Decisions

Decided by the maintainers, 2026-11-16:

- **D1, claim rule source:** the rule's `lookup` reads the token, then userinfo (§5, §6). With userinfo off (the default), it is token-only. TESK is equivalent. (Was Q1.)
- **D2, composition:** claim rule AND decision service; service clients and proTES are handled by leaving the rule unset and expressing them in the PDP (§5). Replaces #113's "PDP decides instead of the rule". (Was Q10.)
- **D3, decision-service failure:** 503 for every failure kind (timeout, connection error, non-200, malformed body); proposing 503 for the TES OpenAPI upstream is optional and not blocking. (Was Q3.)
- **D4, test scope:** the full TES × engine matrix, phased (§8.1): phase 1 Poiesis + OPA + OpenFGA; phase 2 right after: TESK, Funnel and TESP hooks against the same harness.

## 11. Open questions

Numbers kept from draft 3 for stable references; Q1, Q3 and Q10 are decided (§10).

- **Q2, Group sharing in lists.** (a) none in v1; (b) a set ID `group:<g>` with the group stamped on the task; (c) response-context filters. Recommend (a); (b) puts a policy attribute into the TES.
- **Q4, Batch for lists.** Two single calls (any PDP) or one batch call when advertised. Recommend two calls in v1.
- **Q5, Relationship engines.** (a) OpenFGA via the `tes_task` shim (§7); (b) an optional event call writing owner tuples on create. Recommend (a); (b) breaks "one decision call".
- **Q6, Decision caching** in the TES. Recommend none; PDPs can cache.
- **Q7, Entitlements in the access token.** If the IdP can put entitlements into the access token, the userinfo lookup is unnecessary; the design doesn't depend on it. Recommend checking the IdP's tokens for the deployment's client before enabling userinfo.
- **Q8, Profile home.** Keep as `tes-authzen/1` here, or propose to the GA4GH Cloud WS as a TES AuthZ profile. Recommend: prove it in Poiesis and one more TES, then propose.
- **Q9, Owner format for multi-issuer TES.** `<iss>|<sub>` (this draft) vs a hash. Recommend `<iss>|<sub>`: readable, policies can compare it; shims encode where engines restrict IDs (OpenFGA: always, §7).
- **Q11, Owner access after losing the entitlement. Decided (b), 2026-11-16: owners need membership (see change 17).** In a PDP-only deployment (claim rule unset), the reference policy lets owners read and cancel their own tasks without a current entitlement (§7: `owner == subject.id`, or admin). With the claim rule set, the gate blocks such users anyway (D2). Options: (a) keep as is: owners keep access to their own tasks, e.g. to fetch results or cancel running work after leaving a group; (b) require membership on the owner branch too (`member and owner == subject.id`), as suggested during the engine work, so a PDP-only deployment matches a rule-plus-PDP one. Recommend (b): access then ends with the entitlement in both setups (for API keys under `/2`, only when the key expires; see §12), consistent with D2's gate; owners who need results after leaving can be served by an admin, and an operator who wants (a) drops `member` from that branch in their policy. It is a reference-policy choice only; the TES and the contract don't change.

## 12. `tes-authzen/2` (delta to `/1`)

Added 2026-11-22 from Poiesis's implementation (JaeAeich/poiesis, branch `milestone` at `0fa56aa`, `poiesis/api/authz.py` and its authorization docs). `tes-authzen/2` is `/1` plus the additions below; nothing of `/1` is removed, and a `/2` request that uses none of the additions means what it means under `/1`. Three response additions do change what a TES does with a decision: `scope` widens what a `ListTasks` on `own` lists (§3.5), `groups` makes the TES share a new task (and so changes later requests), and `obligations` adds a TES MUST (deny when one is unknown). A TES sends one profile; a decision service that accepts `/2` accepts `/1` too, and the reference decision service (§7) does: its shims and its OPA policy accept `context.tes.profile` `tes-authzen/1` and `tes-authzen/2` and deny any other value.

Request additions **[profile]**:

- `subject.properties.via`: how the caller authenticated, `oidc` (access token) or `apikey` (a TES-issued API key).
- `subject.properties.credential_id`: the credential, when there is one: the token's `jti`, or the key's ID.
- `subject.properties.key_age`, `snapshot_age` (API keys only): seconds since the key was minted; the claims snapshot taken at minting is as old.
- `subject.properties.actor` (delegated tokens only): `{"iss": …, "sub": …}` of the RFC 8693 `act` claim (§7 withholds admin powers from any request that carries it). The subject is still the owner; the policy decides what the actor may do on the subject's behalf.
- `resource.properties.groups` on `tes_task`: the groups the task is shared with (empty unless a `CreateTask` decision shared it, see below).
- TES-specific resource types: Poiesis asks `RevokeApiKeys` and `ListApiKeys` on `poiesis_api_keys` (ID: the owner whose keys are concerned) for admin operations on another owner's API keys. They are outside the TES vocabulary of §3.2 and §3.3.

Response additions **[profile]**: an optional `context.tes` object with `scope` (other owners' tasks a `ListTasks` on `own` may also list: `owners`, `groups`, `tags`), `groups` (the groups to share a new task with, on `CreateTask`), `obligations` (a TES that doesn't know one MUST deny), `advice` (may be ignored) and `reason` (for the log). A plain `{"decision": true|false}` stays a complete answer.

The reference policy (§7) changes in one point with `/2`: a delegated token has no admin powers. It applies this under every profile, whenever `subject.properties` has an `actor` key (also `actor: null`), since a `/1` request with an `actor` is no less delegated. Otherwise it answers with a plain decision, ignores the new subject and task properties, and denies `poiesis_api_keys`, so with it Poiesis's admin operations on other owners' API keys are refused. Its handling of the new properties has two security consequences an operator must weigh **[profile]**:

- A delegated request (with `actor`) keeps the subject's member powers but never gets admin powers, in OPA (`admin` requires no `actor`) and OpenFGA (condition `entitled_undelegated` on the admin tuples, parameter `subject_delegated` from the shim), as in Poiesis's built-in rule. Under `/1` the actor wasn't sent and Poiesis's own delegation guard (actors list, never admin) was the only safeguard; with a decision service that guard no longer applies, so the policy is the safeguard. The reference policy doesn't check who the actor is; operators who don't trust all actors with member powers deny them in their policy.
- An API key's claims are a snapshot taken at minting, so Q11's "access ends with the entitlement" holds for API keys only when the key expires. Operators bound key lifetimes in the TES or refuse old snapshots (`snapshot_age`) in their policy.

Golden cases: `create-profile-2*`, `get-*-profile-2*`, `list-*-profile-2` and `*-admin-actor` extend cases 4b, 7, 9, 10, 12 and 13 to `/2`; `api-keys-*` and `create-wrong-profile` (now `tes-authzen/3`) are contract checks of case 7. `/2` lives in this document on purpose: it is a delta, and `/1` stays valid.

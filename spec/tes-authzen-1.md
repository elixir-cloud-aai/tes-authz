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
17. §7, §11 (superseded by change 22): Q11 decided (2026-11-16, option b): owners need membership. The reference policy's owner branch is `member and owner == subject.id` (OPA) and `(owner and member) or admin` (OpenFGA), so a PDP-only deployment ends owner access when the entitlement is revoked (for API keys under `/2`, only when the key expires; see §12); golden rows for owners without entitlement (get, cancel, near miss). Reference policy only; no TES hook or contract change.

From the Poiesis implementation (2026-11-22):

18. §12 (new): profile `tes-authzen/2`, a compatible extension of `/1` (subject `via`, `credential_id`, `actor`, `key_age`, `snapshot_age`; task `groups`; TES-specific resource types; an optional response `context.tes`). The reference decision service accepts `/1` and `/2`; its policy gives delegated tokens no admin powers.
19. §3.3, §3.5, §7, §12 (2026-11-22, wording only): the reference policy's "no admin with an `actor`" holds under every profile, as implemented and pinned by the golden rows, not only under `/2`; §12 says it also holds under `/1` and with `actor: null`, and names the three response additions that change what a TES does (`scope`, `groups`, `obligations`); §3.3 and §3.5 point to §12; the operator guide's upgrade note names the newly reserved `FGA_CLAIMS` parameter `delegated`.

Owner only (2026-11-24, [#23](https://github.com/elixir-cloud-aai/tes-authz/issues/23); breaking):

20. §3, §3.5, §3.7, §4.1, §6, §8.2: owner by default. Unless an operator switches further operations on (change 26), a TES returns, lists and cancels only the caller's own tasks and decides that itself, without asking the decision service; a missing or foreign task is 404 without a call. Sharing is a client concern; operators act through the infrastructure, not through the TES API.
21. §13 (new): profile `tes-authzen/3` removes `tes_task_set:all` from the request vocabulary. Breaking on purpose: with few implementations so far, it will never be cheaper than now. (Listing every task is now a list scope in the answer, change 27.)
22. §7, §11: the reference policy has no admins. The entitlement is needed only for `CreateTask`; owners keep `GetTask`, `CancelTask` and their own list after losing it (Q11 revised to option (a)); tasks without an owner are reachable by nobody; `ListTasks` on `all` is never allowed; leftover `admins` policy data fails closed.
23. §4.2, §5, §6, §8.2: with any `authz.*` key set, a TES MUST read, list and cancel owner only; Funnel refuses to start unless `TaskAccess` is `Owner` (`All` and `OwnerOrAdmin` don't meet §3; new case 23b); TESK is owner only by default (tesk-api#219).
24. §5, §4.1, §6, §8.2: the built-in claim rule gates `CreateTask` only. It decides who may run tasks; owners keep their own tasks without it, as in the reference policy.
25. §12: the response `scope` and `groups` and `resource.properties.groups` move out of `tes-authzen/2` into "Poiesis extensions (outside the contract)", next to `poiesis_api_keys`; a conforming TES needn't send or honour them.

Operations and list scope (2026-11-25, D6 in §10, [#23](https://github.com/elixir-cloud-aai/tes-authz/issues/23); breaking, part of `tes-authzen/3`):

26. §3, §4.2, §6: a TES asks the decision service on `CreateTask` always, and on `GetTask`, `ListTasks` and `CancelTask` only when the operator switches them on (`authz.operations`, default `[create]`). A switched-on operation is decided by the decision service alone, which may widen it beyond the owner (e.g. group sharing or an admin view in an operator's own policy); operations that aren't switched on stay owner only, decided by the TES. Switched-on `GetTask` and `CancelTask` ask for every requested ID, missing ones too, so the calls don't tell whether a task exists.
27. §3.5: `ListTasks`, when switched on, asks once per page and takes a list scope from the answer: `own` (a plain allow), `all` or `none` (a deny: an empty list, `200`). `all` comes only in `context.tes.list_scope` of an allow, so plain AuthZEN PDPs answer `own` or `none`; the reference policy never answers `all`.
28. §3.1, §3.3, §3.7, §13: every request names owner, caller and operation: `subject` is the caller, `action.name` the operation, `resource.properties.owner` the owner (the stamped owner on `GetTask` and `CancelTask`, the caller on `CreateTask`, absent on `ListTasks` and for missing tasks).
29. §4.1, §4.2: failure behaviour per operation (`authz.failure.<operation>`): `closed` (default, `503`) or `open`, which falls back to the TES's owner rule for that operation, never to allow-all; `create` can't be `open`. The meaning of `open` is a proposal, pending decision (Q12).
30. §8.2: cases 10–15 now apply to switched-on operations; new cases 25–30 (default reads during a decision-service outage, widening, a call per requested ID, list scopes, failure modes, startup checks).

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

A TES keeps three things: authentication (OIDC), an owner stamped on every task, and a thin hook that asks one question per decision. The question is a standard OpenID AuthZEN 1.0 Access Evaluation (`POST /access/v1/evaluation`) that names owner, caller and operation. By default the TES asks only whether the caller may create a task; reading, listing and cancelling are owner only and decided by the TES itself (§3), so a decision-service outage never takes away the caller's results. Operators can hand any of these operations to the decision service (`authz.operations`), which then decides them alone, beyond the owner if its policy says so. Listing then asks one evaluation on the fixed "task set" `own`, whose answer gives the list scope (`own`, `all` or `none`; a plain allow is `own`), and the TES filters in its own store query. Everything that is policy (entitlements, per-action rules, Passport visas) lives in an external decision service of the operator's choice. A built-in, off-by-default claim rule decides with one claim who may create tasks, without extra components. Without configuration, every TES behaves as today.

## 1. Scope and non-goals

| Layer | Does | Doesn't |
|---|---|---|
| Mesh / gateway (Envoy, Istio, ingress) | TLS/mTLS between TES and PDP, rate limits, IP rules, endpoint-level rules (e.g. `/service-info` open), optional coarse `ext_authz` | know task owners, filter lists |
| TES (thin hook) | validate the OIDC access token (issuer, audience, existing `required_scopes`); optional userinfo lookup (identity resolution, §3.6); stamp the owner on create; built-in claim rule; owner rule for operations not switched on; one AuthZEN call per decision; turn the list scope into a store filter; fail closed (or, per operation, fall back to the owner rule) | interpret entitlements, groups, visas, image allowlists, roles |
| Decision service (PDP) | all policy: which entitlements count, per-action rules (e.g. who may create tasks), image or resource limits, Passport/visa validation, token exchange | see the access token; read the TES store |

AuthN is tied to OIDC; AuthZ is agnostic. Reasons: Poiesis accepts only OIDC tokens already, and GA4GH AAI is OIDC-based, with Passports released at userinfo (`ga4gh_passport_v1`).

Non-goals:

- Forwarding the access token to the PDP. At most a later, explicit opt-in (e.g. token exchange). Not in v1.
- Non-OIDC identity sources in v1. The subject stays abstract (`id` plus `iss`, `sub` and claims as properties), so a trusted proxy, mTLS identity or Funnel's Basic users can feed it later without a contract change.
- What a task may do on the cluster (namespaces, quotas, network).
- Sharing tasks with other users, groups or admins in the TES itself (§3, Q2): sharing is a client concern, and operators act through the infrastructure. (A decision service that operators hand reads to may still widen them, §3; that is the operator's policy, not a TES feature.) Decision caching in the TES (Q6); write or event calls to the PDP (Q5).
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

**Operations [profile].** Four operations reach the decision service: `create` (`CreateTask`), `get` (`GetTask`), `list` (`ListTasks`) and `cancel` (`CancelTask`). The operator names in `authz.operations` (§4.2, default `[create]`) the ones the decision service decides; `create` is always among them, since a TES has no create rule of its own.

- **Not switched on (the default for `get`, `list`, `cancel`): owner only, decided by the TES.** A TES MUST NOT return, list or cancel a task for anyone but its owner (the `subject.id` stamped on create, §3.1), and asks no decision service. A missing task, a task of another owner and a task without an exact owner are all 404 for `GetTask` and `CancelTask`; `ListTasks` lists the caller's own tasks. Owners keep their tasks after losing an entitlement, and a decision-service outage doesn't take them away.
- **Switched on: the decision service decides alone.** The TES asks once per decision (§3.5, §3.7, §6) and does what the answer says, also for another owner's task (the decision service may widen an operation beyond the owner, e.g. group sharing or an admin view in an operator's own policy) and also when the answer denies the owner (e.g. a policy that ends access with the entitlement, Q11). `GetTask` and `CancelTask` ask for every requested ID, missing ones too, so that the calls don't tell whether a task exists.

Every request names **owner, caller and operation**: `subject` is the caller (§3.1), `action.name` the operation (§3.2), and `resource.properties.owner` the owner (§3.3): the stamped owner on `GetTask` and `CancelTask`, the caller on `CreateTask`, absent on `ListTasks` and for missing tasks.

There are no admin views in the TES API: sharing belongs in clients (e.g. a portal that acts with each user's own token), and operators inspect or clean up tasks through the infrastructure (database, Kubernetes, logs). The reference policy (§7) is owner only, so switching all four operations on with it gives the same results as the default, except during a decision-service outage (`503` when failing closed, §4.1); an operator who wants more writes it into their own policy and switches the operation on.

### 3.1 Subject

```json
{"type": "user", "id": "<owner id>",
 "properties": {"iss": "...", "sub": "...", "client_id": "...", "scope": ["..."],
                "claims": {"<allowlisted claim>": "..."}}}
```

- The subject is always the caller (for delegated tokens: the token's subject, §12), never the task's owner; the owner is `resource.properties.owner` (§3.3).
- `id`: the string the TES stamps as task owner, so the PDP can compare `subject.id == resource.properties.owner`. A single-issuer TES keeps its existing owner value (no migration): Poiesis `principal_claim` (default `sub`), TESK userinfo `sub`, Funnel token `sub` (or Basic user). **[profile]** A TES that accepts more than one issuer MUST use `<iss>|<sub>` (exactly: issuer string, `|`, subject string; `|` doesn't occur unencoded in an issuer URL, so a reader splits at the first `|`; `sub` may contain `|`, e.g. `auth0|123`). Only `sub`, or `iss`+`sub`, is a safe owner: mutable claims (`email`, `preferred_username`) make ownership hijackable, and the docs must say so.
- `type`: always `user` **[profile]**, also for service clients and for deployments whose `principal_claim` names a group; the PDP tells them apart by `client_id` or claims.
- `properties.iss`, `sub`, `client_id` (`azp` or `client_id` claim), `scope` (as a list): always sent when known (TESK can't fill `client_id` and `scope` for user tokens, §6).
- `properties.claims`: **one resolved claim view** = `{c: lookup(c)}` for each claim `c` named in `authz.decisionService.claims` (default: none). `lookup` (§6) takes the access token and, if userinfo is on, userinfo; when both have a claim, the token value wins. The claim rule uses the same `lookup`, but not the allowlist (§5). This is identity resolution (which value is the user's), not policy: the TES picks no values and interprets none. A TES that can't read the token (TESK validates opaque tokens at userinfo) fills the view from userinfo only and is still equivalent.
- Built only from the validated token and the TES's own userinfo call; never from request headers, query or body. The access token is never sent.

### 3.2 Actions

`action.name` is the TES OpenAPI `operationId` **[profile]**: `CreateTask`, `GetTask`, `ListTasks`, `CancelTask`. `GetServiceInfo` is not checked (open by default in all four; TESK can close it with `tesk.api.service-info.public=false`, which stays as is). `GetTask`/`ListTasks` carry `action.properties.view` (`MINIMAL`/`BASIC`/`FULL`).

### 3.3 Resources

Two types **[profile]** (`tes-authzen/2` adds task `groups` and TES-specific types, §12):

- `tes_task`: a task ID asked about. `id` = task ID. `properties`: `owner`, `state`, `tags` of the stored task. Used for `GetTask` and `CancelTask`, when switched on (§3). A missing task, and a task without an exact owner (TESK legacy tasks, §6), which is treated like a missing one, have `properties: {}`: the TES asks for them like for any other ID, and answers 404 whatever the decision.
- `tes_task_set`: a set of tasks; `id` is `own` (`/1` and `/2` also have `all`, which §13 removes and no conforming TES asks). Used for `CreateTask` (`own`: the new task joins the caller's set; AuthZEN requires an `id`, and no TES knows the new task's ID portably before the decision) and `ListTasks` (§3.5: `own` names the caller's list; the answer may widen or empty it). On `CreateTask`, `properties.owner` is the owner the TES will stamp, i.e. the caller's `subject.id` (`tes-authzen/3`); on `ListTasks` there are no properties.

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

`context.tes`: `{"profile": "tes-authzen/3", "service_id": "<service-info id>"}` **[profile]**. `profile` versions the vocabulary (set IDs, projection fields, owner format), so later changes don't silently change what PDPs receive. `tes-authzen/3` (§13) is the current version; `/1` and `/2` (§12) remain readable by decision services during the move. The TES sends a server-generated `X-Request-ID` (AuthZEN §10.1.3), new for each evaluation (§3.7), never a client-supplied value; trace propagation follows the TES's existing tracing, if any.

### 3.5 List filtering

Not switched on (the default), `ListTasks` asks nothing and lists with `owner = subject.id`.

Switched on, `ListTasks` asks one evaluation per page, `ListTasks` on `tes_task_set:own`, and takes the **list scope** from the answer **[profile]**:

| Answer | List scope | TES does |
|---|---|---|
| `{"decision": false, ...}` | `none` | `200` with an empty list, without a store read |
| `{"decision": true}`, no `context.tes.list_scope` | `own` | list with `owner = subject.id` |
| `{"decision": true, "context": {"tes": {"list_scope": "own"}}}` | `own` | list with `owner = subject.id` |
| `{"decision": true, "context": {"tes": {"list_scope": "all"}}}` | `all` | list without an owner filter |
| `{"decision": true, "context": {"tes": {"list_scope": "none"}}}` | `none` | `200` with an empty list, without a store read |
| an allow whose `context` or `context.tes` isn't an object, or whose `list_scope` has another value or type | – | failed decision (§4.1) |

A deny is `none` whatever its `context`.

A deny is an empty list, not `403`: listing is never forbidden, it just finds nothing the caller may see. `own` stays the request's set ID and a plain allow means `own`, because native AuthZEN PDPs (OpenFGA, Cerbos) return only `decision`; they answer `own` or `none`. `all` is an answer, not a request: only a decision service whose operator grants it sends `list_scope: "all"` (the reference policy never does, §7). `/1` and `/2` also defined `tes_task_set:all` as a request ("list without owner filter"); a TES never asks it (§3), and `tes-authzen/3` removes it from the request vocabulary (§13). Poiesis's response `scope` object (§12) is a different, Poiesis-only field outside the contract; `list_scope` has its own name so that the two can't be confused.

The scope becomes a predicate in the TES's own query (`own`: the caller's owner; `all`: every task with an exact owner, since tasks without one count as missing, §3.3), applied with the user's filters and cursor: pages are correct and complete (no duplicates, no gaps, no task outside the scope), with size ≤ `page_size` (TESK already returns short pages, since it filters names, tags and state after reading a page of jobs). The decision is re-evaluated on every page, with the same scope rules. Keyset cursors (Poiesis, Funnel, TESP) work unchanged, since the scope is applied again on every page. A TES whose page tokens are bound to the store query (Kubernetes continue tokens of a per-owner label selector, TESK) answers `400` for a token whose query no longer matches the page's scope (e.g. the scope changed from `own` to `all` between pages, or the token belongs to another owner). `ListTasks` with `view=FULL` triggers no per-task evaluations.

### 3.6 Userinfo (identity resolution, in the TES)

Part of AuthN. Off by default (`auth.oidc.userinfo.enabled`). Endpoint from OIDC discovery. The userinfo `sub` MUST equal the token's `sub`, else 401. Bounded LRU cache keyed by a hash of the token, entries kept until min(token `exp`, 5 minutes) to limit revocation lag (SHOULD; a TES whose AuthN already looks up userinfo on every request, such as TESK, MAY keep doing so without a cache, which removes the lag; conformance case 21 then doesn't apply). Discovery, JWKS and userinfo calls SHOULD be bounded by one timeout, `auth.oidc.timeout` (seconds, default 10, the value Poiesis hard-codes today for discovery and JWKS, so unset changes nothing). Error, timeout, or a non-JSON response (signed or encrypted userinfo, `application/jwt`, isn't supported) → 401. TESK already does the lookup as its AuthN. Passports delivered via token exchange (GA4GH AAI) are the PDP's concern.

### 3.7 Exact request shape

So that all four TES produce byte-comparable requests (golden files):

- Every request has `subject`, `action`, `resource` and `context`, as in §3.1–§3.4.
- `action.properties` is always present: `{"view": "<MINIMAL|BASIC|FULL>"}` for `GetTask` and `ListTasks`, `{}` for `CreateTask`, `CancelTask` and the extra `GetTask` on the cancel path (no view is requested there; as implemented in Poiesis).
- `tes_task`: `properties` is `{"owner", "state", "tags"}` for a stored task with an exact owner, and `{}` for a missing task or one without an exact owner (§3.3), whoever the owner is.
- `tes_task_set`: no `properties` key on `ListTasks` (`own`); `{"owner": <subject.id>, "task": <projection>}` on `CreateTask` (`tes-authzen/3`; `/1` and `/2` sent `{"task": <projection>}`).
- `subject.properties`: keys with no value are left out (not `null`); `claims` is always present, `{}` when empty.
- Only `CreateTask` and switched-on operations are asked (§3); an operation that isn't switched on sends nothing.
- `X-Request-ID`: newly generated for each evaluation (one per `CreateTask` and per `ListTasks` page, up to two per `CancelTask`), never reused or taken from the client.

Example (`GetTask` switched on, on the caller's own task):

```json
{"subject": {"type": "user", "id": "abc", "properties": {"iss": "https://idp", "sub": "abc", "scope": ["openid"], "claims": {}}},
 "action": {"name": "GetTask", "properties": {"view": "MINIMAL"}},
 "resource": {"type": "tes_task", "id": "0b6c…", "properties": {"owner": "abc", "state": "RUNNING", "tags": {}}},
 "context": {"tes": {"profile": "tes-authzen/3", "service_id": "org.example.tes"}}}
```

## 4. Failure semantics, configuration, security

### 4.1 Failures and status codes

| Situation | Result |
|---|---|
| No or invalid token, userinfo failure | 401 |
| Missing `required_scopes` (Poiesis, existing AuthN check, before the claim rule) | 403 (unchanged) |
| Claim rule fails (CreateTask only, §5) | 403, PDP not called |
| PDP deny on CreateTask | 403 |
| GetTask/CancelTask not switched on: task missing, of another owner, or without an exact owner | 404, PDP not called (§3). Missing and foreign tasks cost the same (no call), also during a PDP outage, so there is no existence oracle |
| ListTasks not switched on | the caller's own tasks, PDP not called |
| GetTask switched on: deny, or allow for a missing task | 404 |
| CancelTask switched on: deny by the PDP | the hook decides `get` once more (asking `GetTask` if `get` is switched on, with `get`'s failure mode; else the owner rule): allowed and the task exists → 403, else 404. When `cancel` isn't switched on, or its decision fell back to the owner rule (`open`), the owner rule makes this choice too, without a call |
| CancelTask switched on: allow for a missing task | 404 |
| ListTasks switched on | by the list scope (§3.5): deny → `none`, empty list (200) |
| Failed decision: PDP timeout (default 2 s), connection error, non-200, body not JSON, `decision` missing or not boolean, malformed list scope | `authz.failure.<operation>` (below): `closed` → 503 **[profile]** with a generic message; cause logged (D3) |

One attempt, no retries. Anything other than `{"decision": true, ...}` is a deny. Residual: the store read for a missing ID is slightly faster than for an existing one; accepted and documented. Switched-on `GetTask` and `CancelTask` ask for missing and foreign IDs too, so a decision service that is down answers `503` for every ID alike (no existence oracle); probing random IDs then costs one PDP call each, so rate limiting is the mesh's job (§1). `ListTasks` is not gated by the claim rule, so with `list` switched on every authenticated caller costs one PDP call per page; rate limiting (of `ListTasks` too) is the mesh's job.

**Failure behaviour per operation [profile]** (`authz.failure.<operation>`, one key per operation of §3):

- `closed` (default, every operation): a failed decision is `503`, nothing is executed.
- `open` (`get`, `list`, `cancel` only): a failed decision falls back to the TES's owner rule for that operation, as if the operation weren't switched on: own tasks are served, missing and foreign ones are 404, lists are owner only. It never falls back to allow-all, and the fallback is logged. `create` can't be `open` (the TES refuses to start, §4.2): a TES has no create rule of its own, so falling open would let every authenticated caller create tasks.

The meaning of `open` is a proposal, pending decision (Q12); `closed` and the default are settled. An operator who switches an operation on in order to widen it (§3) and sets it to `open` accepts that during an outage the operation is owner only; one who switches it on to narrow it (e.g. to end access with the entitlement, Q11) and sets `open` accepts that owners keep access during an outage.

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
| `authz.operations` | operations the decision service decides (§3): a list of `create`, `get`, `list`, `cancel`; default `[create]`; must contain `create` |
| `authz.failure.<operation>` | `closed` (default) or `open` per operation (§4.1); `authz.failure.create` must be `closed`; `open` is provisional until Q12 is decided |

List-valued settings (`requiredClaim.values`, `requiredClaim.prefixes`, `decisionService.claims`, `operations`) are JSON arrays when given as environment variables (group URNs can contain commas), e.g. `POIESIS_AUTHZ_REQUIRED_CLAIM_PREFIXES='["urn:geant:lifescience-ri.eu:group:vo:"]'`; config files and Helm values use their native lists. Existing CSV settings (Poiesis `POIESIS_AUTH_OIDC_REQUIRED_SCOPES`) stay CSV. Mapping: Poiesis env `POIESIS_` + upper snake (`POIESIS_AUTHZ_DECISION_SERVICE_URL`), Helm values verbatim. TESK Spring `tesk.api.authz.decision-service.url` (env `TESK_API_AUTHZ_DECISION_SERVICE_URL`) and a new `tesk.api.authz.required-claim.{name,values,prefixes}`, enforced as an AND gate before the SpEL expression of `CreateTask` only (§5). TESK's existing `tesk.api.authorisation.claim.*` is not reused: it sets `claimAuthorised`, an OR grant that admits users without groups (`isAuthorisedWithoutGroup()`, ORed with group membership in `TesService`'s `@PreAuthorize`), so reusing it would change existing deployments or make TESK's rule an OR. It stays part of TESK's built-in group model. TESK also needs `tesk.api.authz.issuer` (env `TESK_API_AUTHZ_ISSUER`), required with the decision service, because its opaque-token userinfo doesn't name the issuer; it fills `subject.properties.iss` and the `<iss>|<sub>` owner. TESK maps `authz.operations` and `authz.failure.<operation>` to `tesk.api.authz.operations` and `tesk.api.authz.failure.<operation>`. Funnel YAML `Server.Authz.DecisionService.URL`. TESP Dynaconf `[authz] decision_service.url`, env `TESP_API_AUTHZ__DECISION_SERVICE__URL`. #113 proposed `POIESIS_AUTH_OIDC_REQUIRED_CLAIM*`; the rule moves under `authz` because it decides (note on #113, §9).

Startup checks: `authz.*` set while auth is disabled → refuse to start (no anonymous principal reaches a PDP). `authz.*` set while the TES's own read rule isn't owner only (Funnel `TaskAccess` other than `Owner`) → refuse to start (§5). `requiredClaim.name` without values and prefixes → refuse to start. `authz.operations` other than `[create]` or any `authz.failure.*` without `authz.decisionService.url`, `authz.operations` without `create` or with an unknown or repeated value, `authz.failure.*` for an unknown operation or with a value other than `closed`/`open`, or `authz.failure.create: open` → refuse to start. Implementations SHOULD also refuse to start on (fail-safe checks from Poiesis): an empty string among `values` or `prefixes` (an empty prefix matches everything); any `authz.decisionService.*` key set without `url`, or a `url` that isn't `http(s)://` with a host; a `credentialFile` that is empty or unreadable. A non-loopback `http://` PDP URL → warning only: AuthZEN §11.1 requires a secured PEP–PDP connection, which a mesh (mTLS sidecar) usually provides; transport is the mesh's job.

### 4.3 Security

- No identity spoofing: the subject comes only from the validated token (issuer and audience pinned) and the TES's own userinfo call; the owner is stamped server-side; client-supplied owner-like fields are ignored; client task IDs are ignored (§3.3).
- No token forwarding (§1).
- Transport: loopback sidecar, mesh mTLS or HTTPS; a NetworkPolicy so only the TES reaches the PDP; the optional PEP credential from a file, never an env var.
- Logs: decision, action, resource ID, request ID; never tokens or claim values.

## 5. Built-in claim rule and composition

Rule: allowed if the claim `lookup(rule.name)` (§6: exact name, then dotted path; token first, then userinfo; with userinfo off, the access token only; independent of the PDP allowlist) is a string or list of strings with a value equal to one of `values` or starting with one of `prefixes`. Prefixes are raw string prefixes: operators include the delimiter. LS Login recipe: the group itself as an exact value (`urn:geant:lifescience-ri.eu:group:vo#<authority>`, authority as released by LS Login) plus `urn:geant:lifescience-ri.eu:group:vo:` as prefix for its subgroups; a prefix without the trailing `:` would also admit `…:group:vo2#…`. Off when `name` is unset. Missing claim or wrong type → deny.

Scope **[profile]**: the rule gates `CreateTask` only. It decides who may run tasks; `GetTask`, `CancelTask` and `ListTasks` are decided by the owner rule or, when switched on, by the decision service (§3), and an owner keeps their tasks after losing the claim.

Composition: claim rule AND decision on `CreateTask`. Order: token (issuer, audience, `required_scopes`) → userinfo (if on) → claim rule (`CreateTask`) or store read (get/cancel) → decision (PDP for `CreateTask` and switched-on operations, else the built-in owner rule). On `CreateTask` both must allow.

Why AND, not "the PDP replaces the rule" (#113's wording): the rule is an admission gate ("who may run tasks on this service"), the PDP decides "what may this user do". With AND, each is meaningful alone, unset is a no-op, an operator who wants PDP-only leaves the rule unset, and a misconfigured PDP can't let anyone create beyond the gate. Reads are bounded by the owner rule of §3 unless the operator hands them to the decision service. Cost: one local comparison.

Consequence: every caller that creates tasks must carry the claim. Client-credentials tokens (service clients, and proTES, which the TES sees as the caller, §1) carry no user entitlements, so they get 403 on `CreateTask` when the rule is set. Deployments with service clients or behind proTES leave the rule unset and express "entitled users or client X" in the PDP's policy data (e.g. a list of `(iss, client_id)` pairs matched against `subject.properties.iss` and `client_id`, with `sub` equal to the client ID); the TES's own list of service clients serves authentication only. No OR or exemption keys in the TES: that would be policy. The operator docs say so. Like any creator, a service client then owns its tasks and gets, lists and cancels them by the owner rule.

Built-in default (no PDP): Poiesis and TESP: today's owner rule (create allowed; get/cancel/list own tasks). TESK: owner only by default (tesk-api#219). Funnel keeps `TaskAccess` (default `All`: every authenticated user sees every task; `OwnerOrAdmin`: admins see every task); neither meets §3. With any `authz.*` key set (claim rule or PDP), a TES MUST read, list and cancel owner only for every operation that isn't switched on **[profile]**: Funnel then refuses to start unless `TaskAccess` is `Owner` (with or without a PDP), since the claim rule no longer gates reads and would otherwise leave every task open to every authenticated user. Switched-on operations are decided by the PDP alone (§3). Explicit opt-ins outside the contract (Poiesis `authz.sharing`, `authz.adminRead`, §12) are excluded from this MUST: a deployment that turns them on knowingly leaves the contract, and their reach is then no longer limited by the claim rule. Equivalence across implementations is required for the claim rule and the PDP path only.

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
                                  context:{tes:{profile:"tes-authzen/3", service_id}}}
                      timeout, X-Request-ID = server-generated
                    return body if body.decision is a boolean; on any failure raise Failed
on(op)            = pdp and op in authz.operations                   # create always; get/list/cancel opt-in
fallback(op)      = authz.failure[op] == "open"                       # default closed; never for create

CreateTask(p, task):  gate(p); drop client id/state/creation_time/logs
                      res = {type:"tes_task_set", id:"own", properties:{owner:p.owner_id, task:project(task)}}
                      if on("create") and not ask(p,"CreateTask",res).decision: 403   # Failed: 503
                      task.owner = p.owner_id; store(task)
meta(t)           = {} if t is None else {owner, state, tags}
owner_rule(p, t)  = t is not None and t.owner == p.owner_id
allowed(op, act, p, id, t, aprops)                                    # returns (allowed, decided by the PDP)
                  = if on(op):
                        try: return (ask(p, act, {type:"tes_task", id, properties:meta(t)}, aprops).decision, true)
                        except Failed: if not fallback(op): raise 503; log the fallback
                    return (owner_rule(p, t), false)                  # no PDP call; owners keep their tasks
GetTask(p, id, view): t = store.read_meta(id)                         # None if missing or without an exact owner
                      if not allowed("get","GetTask",p,id,t,{view})[0] or t is None: 404
CancelTask(p, id):    t = store.read_meta(id)
                      ok, pdp_decided = allowed("cancel","CancelTask",p,id,t,{})
                      if not ok:
                          # 403/404: ask get only if the PDP denied cancel; an owner-rule deny
                          # (not switched on, or fell open) uses the owner rule again, no call
                          readable = allowed("get","GetTask",p,id,t,{})[0] if pdp_decided else owner_rule(p,t)
                          if readable and t is not None: 403 else 404
                      if t is None: 404
                      proceed
ListTasks(p, f, view):scope = "own"
                      if on("list"):
                          try: scope = list_scope(ask(p,"ListTasks",{type:"tes_task_set",id:"own"},{view}))
                          except Failed: if not fallback("list"): raise 503; log the fallback
                      if scope == "none": return []                    # no store read
                      store.list(f + (owner=p.owner_id if scope == "own" else has an exact owner))
list_scope(a)     = "none" if not a.decision else a.context.tes.list_scope or "own"
                    # must be "own", "all" or "none"; a malformed context or another value raises Failed
```

**Poiesis** (`poiesis/api/auth.py`, `routes/tasks.py`, `db/tasks.py`, `settings.py`). A new `authz.py` holds `gate`, `ask`, `subject` and the list scope; the `CreateTask` route runs the gate. `Principal.claims` already has the validated claims. `principal_claim` keeps its current lookup (`_walk_claim_path`, dotted path only): making it exact-name-first would silently change task owners in existing deployments whose claim names contain dots. Exact-name-first applies only to `lookup` (claim rule and allowlist), a new helper. A cheap owner/state/tags query reads the metadata; by default anything not owned by the caller is 404 without a PDP call, and switched-on get/cancel ask for every ID (§3). Lists keep `filters.principal` set unless the list scope is `all`; keyset cursor unchanged. `authz.operations` and `authz.failure.*` are new settings. Poiesis's `authz.sharing` and `authz.adminRead` are extensions outside the contract (§12): a deployment that turns them on doesn't meet §3. Also: ignore client task IDs. Hard: little; `principal_claim` may differ from `sub`, so `subject.id` and `properties.sub` can differ.

**TESK** (`config/security/ResourceServerConfiguration.java`, `tes/service/TesService.java`, `TesServiceImpl.java`, `k8s/service/KubernetesClientWrapper.java`, `CreatorLabels`). The decision lives in a Spring bean (`@tesAuthz`) called from the existing `@PreAuthorize`/`@PostAuthorize` SpEL; the bean switches on "PDP set?" because annotations are static. AuthN is userinfo introspection, so the resolved view comes from userinfo only; `User` must keep `iss` and the raw userinfo claims. Subject properties TESK can't fill for user tokens: `client_id` and `scope` (userinfo carries neither); service-client tokens are decoded (`ServiceClientTokenServices`) and fill them. TESK gets its own golden values for these fields, and policies that must work with TESK don't use `scope`/`client_id` to judge users. By default only `CreateTask` asks (`tesk.api.authz.operations`, default `[create]`), and missing and foreign tasks are 404 without a PDP call (§3), which is what TESK's not-found path does already. List uses the creator hash label for the scope `own` and no owner selector for `all`; `none` makes no Kubernetes call. Continue tokens are bound to the selector, so a token used under another scope or by another owner is 400 (§3.5). Owner = the creator annotation (exact ID, checked against the hash label). Legacy tasks (only `creator-user-id`, lossy `@`→`_`) have no exact owner, so they are treated as missing (§3.3) and nobody reaches them; operators with legacy tasks keep the built-in model until those tasks expire, or clean them up in the cluster. The group model (`GROUP_NAME`, managers) is not part of the contract.

**Funnel** (`internal/server/auth/auth.go`, `auth_oidc.go`, `internal/identity/identity.go`, `internal/server/taskservice/service.go`, backends in `internal/database/*/tes.go`). The hook covers the four TES RPCs only; it runs in the task service, below the gRPC interceptor, so the gRPC and HTTP-gateway paths both pass it. The interceptor must keep `iss` and the validated claims (today `sub` and the token). List: always the owner filter (`CanSeeAllTasks()` false), no backend change. Get/cancel: owner checks sit inside each backend (`IsAccessible`), so the hook reads with a system identity in the task service only, decides, then proceeds. `IsAccessible` uses in events, reservations and execution claims (worker paths) stay as they are. With any `authz.*` key set, Funnel refuses to start unless `TaskAccess` is `Owner` (§5); switched-on operations are decided by the PDP (§3). Basic users have no `iss` (abstract subject, `iss` omitted). Hard: the central read-decide wrapper over 6 backends.

**TESP** (`tesp_api/api/endpoints/endpoint_utils.py`, `task_endpoints.py`, `repository/task_repository.py`, `utils/token_validator.py`, `config/properties.py`). The hook relies on pinned issuer(s) and audience (§4.3). With more than one issuer, owners become `<iss>|<sub>`, with a migration that backfills `author = "<pinned iss>|" + author` for existing tasks. Then `parse_verify_token` returns a principal; `author` is the owner, and every read and list filters by it. Hard: the pymonad `Promise` chains make read-decide-proceed awkward.

## 7. Reference decision service and engines

Reference service: a small AuthZEN PDP (`/access/v1/evaluation` plus `/.well-known/authzen-configuration`) whose behaviour is set by one policy. The reference deployment is one configuration of it:

- CreateTask on `own`: `subject.properties.claims.eduperson_entitlement` contains the group (exact) or a subgroup (prefix `…:vo:`); optional image prefix allowlist on `resource.properties.task.executors[].image`. This is the only action that needs the entitlement.
- GetTask/CancelTask: `resource.properties.owner == subject.id` (owner present and not empty), also after the entitlement was revoked (Q11, revised to (a)); a missing owner → nobody.
- ListTasks: a plain allow for every caller, i.e. the list scope `own` (§3.5); never `all` (that would be an operator's own policy, answering `context.tes.list_scope: "all"`). With `list` switched on, callers without the entitlement still list their own tasks.
- CreateTask under `tes-authzen/3`: `resource.properties.owner` must equal `subject.id` (§3.3); anything else is a contract error (deny).
- Owner only: with the reference policy, switching `get`, `list` and `cancel` on (§3) changes no result; it only adds calls (and `503` during an outage when failing closed).
- Service clients: their create grant belongs in the policy data, not in the TES (§5); the reference policy data has no service clients yet, so client-credentials tokens are denied `CreateTask`.
- No admins: no entitlement reaches another owner's tasks. An `actor` (§12) changes nothing, since there are no admin powers to withhold. Policy data that still has an `admins` key fails closed: OPA denies every request, and the OpenFGA setup job refuses to start.
- Optional: Passport visas (`ga4gh_passport_v1`) validated here, never in the TES.

Generic shim step, shared by all shims (not policy): **prefix expansion** adds, for each string value of a list-valued claim, the set of its prefixes ending at a delimiter (e.g. `a:b:c#x` → `a:`, `a:b:`, `a:b:c#x`), so engines without quantifiers (Cedar, Casbin) can test "has a subgroup of" with set membership. The delimiter set is a shim setting (default `:`; e.g. `/` for Keycloak group paths). Reference-policy prefixes must end in a delimiter, or Cedar and Casbin will decide differently from OPA's `startswith` (verified on the golden entitlement sets). OPA and OpenFGA test prefixes natively and don't use expansion.

| Engine | How it plugs in | Adapter | Native vs shim |
|---|---|---|---|
| OPA (reference) | Rego reads the AuthZEN request as `input`; a front of about 60 lines (verified) → `POST /v1/data/tes/allow`, or the community `opa-authzen-plugin` | thin | all policy in Rego; `some`/`startswith` native |
| OpenFGA | experimental AuthZEN (`OPENFGA_EXPERIMENTALS=authzen`), store-scoped path `/stores/{id}/access/v1/evaluation` | thin shim for `tes_task` | Evaluation is a Check: `action.name` must be a relation, a Check needs a stored tuple, no object wildcards, no contextual tuples in its AuthZEN binding; properties arrive as `subject_*`/`resource_*` condition context (all per openfga.dev/docs/interacting/authzen). So `tes_task_set:own` works natively (fixed objects, `user:*` tuples; `all` gets no tuple, so it is always denied); for `tes_task:<id>` the shim rewrites the object to `tes_service:<service_id>` with a conditioned `user:*` tuple (`resource_owner == subject_id`). OpenFGA returns an error (400), not a deny, when a condition parameter is missing, and `subject.id` isn't in its condition context (only `subject_*` properties are); both verified. So the shim always passes `resource_owner` (empty string when absent: missing or legacy tasks) and `subject_id` in the context; otherwise missing tasks would give 503 instead of 404. IDs (verified): subjects must match `^[^:#@\s]{1,500}$`, objects `^[^:#@\s]{1,256}$`, so every `<iss>|<sub>` owner and every LS Login `sub` (`…@lifescience-ri.eu`) is rejected as is: the shim encodes every subject ID (ours hashes all of them) and passes the real ID as `subject_id`. Prefix tests run natively in CEL (`exists`, `startsWith`), no expansion. CEL cost (verified): with the default `OPENFGA_MAX_CONDITION_EVALUATION_COST`, a condition over more than about 5 entitlements or executors fails with 400, i.e. 503 at the TES for ordinary LS Login users; the reference deployment raises the budget, the shim caps lists at 1024 items (502 above that) and checks the worst case at setup. Body limit: OpenFGA's gRPC gateway rejects requests over about 602 KiB, so the shim accepts at most 512 KiB. Unknown action names give 400 in OpenFGA; the shim validates them first and denies. Alternative: owner tuples written on create (Q5) |
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
| 5 | rule set, claim missing or no match | CreateTask / GetTask, CancelTask, ListTasks | 403, PDP not called / not gated: decided as without the rule |
| 5e | rule set, owner without the claim | GetTask / ListTasks / CancelTask on own task | 200 / own tasks / 200 |
| 5b | rule set (`values=[a]`), no PDP, empty claims allowlist | CreateTask with claim `a` | 200 (rule doesn't depend on the allowlist) |
| 5c | rule set by dotted path `ctx.groups` / by URI name `https://e.org/groups` | CreateTask with matching claim | 200 |
| 5d | rule set, client-credentials token without the claim | CreateTask | 403 |
| 6 | rule set, claim is a list with one match | CreateTask | 200 |
| 6b | userinfo on, claim only in userinfo / in both with different values | CreateTask with rule and PDP | rule and `properties.claims` use userinfo value / token value |
| 7 | PDP allows | CreateTask | 200; owner = subject.id; request = golden `create` (URLs stripped, no `backend_parameters`, `context.tes.profile`) |
| 7b | PDP allows | CreateTask with client `id`, `state` | server-assigned ID and state |
| 8 | PDP denies | CreateTask | 403, nothing stored |
| 9 | PDP allows everything; default operations | GetTask / CancelTask on another's task | 404 / 404; PDP not called; task unchanged |
| 10 | `get`, `cancel` switched on; PDP denies GetTask and CancelTask | GetTask / CancelTask on an own task | 404 / 404; task unchanged |
| 10b | `get`, `cancel` switched on; PDP allows GetTask, denies CancelTask / only `cancel` switched on, PDP denies it | CancelTask on an own task / on an own and a foreign task / only `get` switched on, PDP allows everything: CancelTask on a foreign task | 403 / 403 and 404 / 404, no `CancelTask` or `GetTask` call |
| 11 | PDP allows or denies; default operations | GetTask / CancelTask on missing ID | 404; PDP not called |
| 11b | `get`, `list`, `cancel` switched on, failing closed; PDP down | GetTask and CancelTask on an own, a missing and a foreign ID; ListTasks | 503 for all (no existence oracle) |
| 11c | PDP allows; default operations | CancelTask on a missing and on a foreign ID | 404 for both; PDP not called |
| 11d | `get`, `cancel` switched on; PDP denies | CancelTask on an own task | 404; PDP asked `CancelTask`, then `GetTask`, with the task's properties and distinct request IDs; if the `GetTask` call fails (get closed): 503 |
| 12 | PDP allows everything (plain allow); default operations / `list` switched on | ListTasks, pages of 2 | only own tasks, complete, no duplicates; no call / `ListTasks` on `own` once per page; `all` never asked |
| 13 | default operations | ListTasks, pages of 1 | only own tasks, complete, no duplicates, sizes ≤ 1 |
| 14 | PDP denies everything; `list` switched on / default operations | ListTasks | 200 with an empty list (scope `none`), only `own` asked / the caller's own tasks, PDP not called |
| 15 | operation switched on; PDP times out / 500 / `{"decision":"true"}` / no `decision` | any action | 503, logged, nothing executed |
| 16 | PDP set, rule fails | CreateTask | 403, PDP not called |
| 17 | rule passes, PDP denies | CreateTask | 403 |
| 18 | client sends `X-Request-ID`, identity headers, owner-like tags | CreateTask | subject from token only; PDP sees a server-generated request ID |
| 19 | allowlist `[eduperson_entitlement]` | any | `properties.claims` has only that claim; no token anywhere in the request |
| 20 | userinfo on; userinfo `sub` differs (not applicable for opaque-token TESes, i.e. TESK: no token `sub` to compare) / endpoint down / slower than `auth.oidc.timeout` / `application/jwt` | any | 401 |
| 21 | userinfo on, two calls with one token | any ×2 | one userinfo call |
| 22 | built-in default (no PDP) | GetTask on another's task / ListTasks | per TES (Poiesis, TESP, TESK: 404 / own only; Funnel: per `TaskAccess`; with `authz.*` set it must be `Owner`, case 23b) |
| 23 | authz set, auth disabled | startup | refuses to start |
| 23b | Funnel only: `authz.*` set (claim rule or PDP), `TaskAccess` `All` or `OwnerOrAdmin` | startup | refuses to start |
| 24 | Funnel only | cases 7, 10, 13 over gRPC | same results as over HTTP |
| 25 | default operations; PDP down | CreateTask; GetTask, ListTasks, CancelTask on own and foreign tasks | 503; own tasks 200 and listed, foreign 404; only `CreateTask` asked |
| 26 | `get`, `cancel` switched on; PDP allows everything | GetTask / CancelTask on another owner's task | 200 / 200 (the decision service widens); requests name the task's owner and the caller |
| 27 | `get`, `cancel` switched on | GetTask on an own, a foreign and a missing ID; CancelTask on a missing ID | one call per ID, the missing one with `properties: {}`; 404 on deny, and for the missing ID also on allow |
| 28 | `list` switched on; answer plain allow / `list_scope` `own` / `all` / `none` / deny / unknown or malformed scope | ListTasks, pages of 1 | own tasks / own tasks / every task / empty / empty / 503 |
| 29 | `get`, `list`, `cancel` switched on, `authz.failure` `open` for all three / for `list` only; PDP down | each operation on own and foreign tasks | owner rule (own 200, foreign and missing 404, own list) / list owner only, get and cancel 503; `CreateTask` 503; only `cancel` open: a foreign or missing cancel is 404 without a `GetTask` call |
| 30 | `authz.operations` without `create`, unknown operation or failure value, `authz.failure.create: open`, switch without a PDP URL | startup | refuses to start |

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
- **D2, composition:** claim rule AND decision service (the rule gates `CreateTask` only since D5); service clients and proTES are handled by leaving the rule unset and expressing them in the PDP (§5). Replaces #113's "PDP decides instead of the rule". (Was Q10.)
- **D3, decision-service failure:** 503 for every failure kind (timeout, connection error, non-200, malformed body); proposing 503 for the TES OpenAPI upstream is optional and not blocking. (Was Q3.)
- **D4, test scope:** the full TES × engine matrix, phased (§8.1): phase 1 Poiesis + OPA + OpenFGA; phase 2 right after: TESK, Funnel and TESP hooks against the same harness.

Decided by the maintainers, 2026-11-24 (elixir-cloud-aai/generic-issues#124):

- **D5, owner only:** list, get and cancel only by the owner, admins included; no group sharing in the TES; sharing is a client concern; operators act through the infrastructure; group membership only decides who may create tasks, so the claim rule gates `CreateTask` only (§3, §5, §7, §13). Decides Q2 (none) and revises Q11 (option (a)).

Decided by the maintainers, 2026-11-24 (for TESK first, adopted here as the contract):

- **D6, operations and list scope:** by default only `CreateTask` asks the decision service; `GetTask`, `ListTasks` and `CancelTask` are decided by the TES (owner == caller), and operators can switch any of them on (`authz.operations`), in which case the decision service decides them fully and may widen them beyond the owner (e.g. group sharing or an admin view in someone else's deployment). Every request names owner, caller and operation. `ListTasks` asks once per page and gets a list scope (`own`, `all`, `none`) that the TES applies as a filter; `all` only where an operator's policy grants it. Failure behaviour is set per operation and fails closed by default. The reference policy stays owner only, so all four operations switched on with it give the default's results; D5's "no admin view" describes the reference policy and deployments using it, not a limit of the contract (§3, §3.5, §4.1, §4.2, §13). Reason: TES implementations are written for others; versatility without losing robustness (a decision-service outage no longer blocks results or cancelling by default).

## 11. Open questions

Numbers kept from draft 3 for stable references; Q1, Q3 and Q10 are decided (§10); Q12 is new.

- **Q2, Group sharing in lists. Decided (a), none (D5).** (a) none; (b) a set ID `group:<g>` with the group stamped on the task; (c) response-context filters. Sharing belongs in clients.
- **Q4, Batch for lists.** Two single calls (any PDP) or one batch call when advertised. Recommend two calls in v1.
- **Q5, Relationship engines.** (a) OpenFGA via the `tes_task` shim (§7); (b) an optional event call writing owner tuples on create. Recommend (a); (b) breaks "one decision call".
- **Q6, Decision caching** in the TES. Recommend none; PDPs can cache.
- **Q7, Entitlements in the access token.** If the IdP can put entitlements into the access token, the userinfo lookup is unnecessary; the design doesn't depend on it. Recommend checking the IdP's tokens for the deployment's client before enabling userinfo.
- **Q8, Profile home.** Keep as `tes-authzen/1` here, or propose to the GA4GH Cloud WS as a TES AuthZ profile. Recommend: prove it in Poiesis and one more TES, then propose.
- **Q9, Owner format for multi-issuer TES.** `<iss>|<sub>` (this draft) vs a hash. Recommend `<iss>|<sub>`: readable, policies can compare it; shims encode where engines restrict IDs (OpenFGA: always, §7).
- **Q11, Owner access after losing the entitlement. Decided (b), 2026-11-16 (change 17); revised to (a), 2026-11-24 (D5, change 22): owners keep get, cancel and their own list; the entitlement is needed only to create.** The text below is the original question. In a PDP-only deployment (claim rule unset), the reference policy lets owners read and cancel their own tasks without a current entitlement (§7: `owner == subject.id`, or admin). With the claim rule set, the gate blocks such users anyway (D2). Options: (a) keep as is: owners keep access to their own tasks, e.g. to fetch results or cancel running work after leaving a group; (b) require membership on the owner branch too (`member and owner == subject.id`), as suggested during the engine work, so a PDP-only deployment matches a rule-plus-PDP one. Recommend (b): access then ends with the entitlement in both setups (for API keys under `/2`, only when the key expires; see §12), consistent with D2's gate; owners who need results after leaving can be served by an admin, and an operator who wants (a) drops `member` from that branch in their policy. It is a reference-policy choice only; the TES and the contract don't change.
- **Q12, What `open` means in `authz.failure.<operation>`.** D6 makes failure behaviour configurable per operation and fixes the default (`closed`: `503`), but leaves the meaning of `open` open. Proposed (§4.1): (a) fall back to the TES's owner rule for that operation (own tasks served, foreign and missing 404, own list), never to allow-all, and `create` can't be `open` (startup check), since a TES has no create rule of its own. Alternatives: (b) no `open` at all (only `closed`), which keeps every TES simpler but makes a switched-on read unavailable during an outage; (c) `open` = allow, which for a switched-on `get` or `list` would show every task to every caller during an outage. Recommend (a). The reference tooling (mock TES, cases 29 and 30) implements (a); (b) would only remove the value, (c) is rejected.

## 12. `tes-authzen/2` (delta to `/1`)

Added 2026-11-22 from Poiesis's implementation (JaeAeich/poiesis, branch `milestone` at `0fa56aa`, `poiesis/api/authz.py` and its authorization docs). `tes-authzen/2` is `/1` plus the additions below; nothing of `/1` is removed, and a `/2` request that uses none of the additions means what it means under `/1`. One response addition changes what a TES does with a decision: `obligations` adds a TES MUST (deny when one is unknown). A TES sends one profile; a decision service that accepts `/2` accepts `/1` too, and the reference decision service (§7) does: its shims and its OPA policy accept `context.tes.profile` `tes-authzen/1`, `/2` and `/3` (§13) and deny any other value. The owner-only rule of §3 for operations that aren't switched on applies under `/2` as under every profile; the operation switch, the list scope and the owner on `CreateTask` are defined by `/3` (§13).

Request additions **[profile]**:

- `subject.properties.via`: how the caller authenticated, `oidc` (access token) or `apikey` (a TES-issued API key).
- `subject.properties.credential_id`: the credential, when there is one: the token's `jti`, or the key's ID.
- `subject.properties.key_age`, `snapshot_age` (API keys only): seconds since the key was minted; the claims snapshot taken at minting is as old.
- `subject.properties.actor` (delegated tokens only): `{"iss": …, "sub": …}` of the RFC 8693 `act` claim. The subject is still the owner; the policy decides what the actor may do on the subject's behalf.

Response additions **[profile]**: an optional `context.tes` object with `obligations` (a TES that doesn't know one MUST deny), `advice` (may be ignored) and `reason` (for the log). A plain `{"decision": true|false}` stays a complete answer.

**Poiesis extensions (outside the contract).** Poiesis also sends or honours the following; a conforming TES needn't send or honour them, and decision services needn't know them. A Poiesis deployment that turns on `authz.sharing` or `authz.adminRead` (both off by default) lets non-owners see tasks and so doesn't meet §3 while they are on.

- `resource.properties.groups` on `tes_task`: the groups the task is shared with.
- Response `context.tes.scope` (other owners' tasks a `ListTasks` on `own` may also list: `owners`, `groups`, `tags`) and `context.tes.groups` (the groups to share a new task with, on `CreateTask`).
- TES-specific resource types: `RevokeApiKeys` and `ListApiKeys` on `poiesis_api_keys` (ID: the owner whose keys are concerned), for admin operations on another owner's API keys. They are outside the TES vocabulary of §3.2 and §3.3.

The reference policy (§7) answers with a plain decision, ignores the new subject and task properties, and denies `poiesis_api_keys`, so with it Poiesis's admin operations on other owners' API keys are refused. It has no admin powers, so an `actor` changes nothing: a delegated request has its subject's powers. Two security consequences an operator must weigh **[profile]**:

- The reference policy doesn't check who the actor is; operators who don't trust all actors with their subjects' powers deny them in their policy. Under `/1` the actor wasn't sent and Poiesis's own delegation guard (actors list) was the only safeguard; with a decision service that guard no longer applies, so the policy is the safeguard.
- An API key's claims are a snapshot taken at minting, so revoking an entitlement stops `CreateTask` with that user's keys only when the keys expire. Operators bound key lifetimes in the TES or refuse old snapshots (`snapshot_age`) in their policy.

Golden cases: `create-profile-2*`, `get-*-profile-2*`, `list-*-profile-2` and `*-admin-actor` extend cases 4b, 7, 9, 10, 12 and 13 to `/2`; `api-keys-*` and `create-wrong-profile` (`tes-authzen/4`) are contract checks of case 7. `/2` lives in this document on purpose: it is a delta, and `/1` stays readable.

## 13. `tes-authzen/3` (delta to `/2`)

Added 2026-11-24 (D5) and extended 2026-11-25 (D6), both [#23](https://github.com/elixir-cloud-aai/tes-authz/issues/23). `tes-authzen/3` is `/2` with these changes **[profile]**:

- **No `tes_task_set:all` in requests:** the only task set is `own` (§3.3, §3.5). Breaking on purpose: a `/3` request on `all` is outside the profile, and decision services deny it (the reference shims as a contract error).
- **Operations (§3):** `CreateTask` always asks; `GetTask`, `ListTasks` and `CancelTask` ask only when switched on (`authz.operations`), and are owner only, decided by the TES, otherwise. Switched-on `GetTask` and `CancelTask` ask for every requested ID, a missing one with `properties: {}`.
- **Owner, caller and operation in every request (§3, §3.3):** `CreateTask` carries `resource.properties.owner`, equal to `subject.id`; decision services deny a `/3` `CreateTask` without it or with another value (the reference shims as a contract error).
- **List scope (§3.5):** a `ListTasks` answer may carry `context.tes.list_scope` (`own`, `all`, `none`); a deny is `none` (an empty list, `200`, where `/1` and `/2` gave `403`).
- **Failure per operation (§4.1):** `authz.failure.<operation>`, `closed` by default.

Together with the owner-only default of §3, no decision of the reference policy can make a TES list, return or cancel another owner's task; an operator's own policy can, for switched-on operations only.

Moving from `/2` (or `/1`) to `/3`: a TES sends the owner on `CreateTask`, stops asking about `GetTask`, `ListTasks` and `CancelTask` unless switched on, and treats a `ListTasks` deny as an empty list. Order: deploy a decision service that accepts `/3` (this repository's reference services from #23 on), then switch the TES. The reference decision service decides `/1`, `/2` and `/3` alike (owner only); it denies `all` under every profile and never answers a list scope other than `own` (a plain allow).

Golden cases: `*-profile-3` extend cases 5, 5e, 7, 9, 10, 11, 13, 14 and 26–28 to `/3` (`list-all-*-profile-3` and `create-on-all-profile-3`: `all` is denied; `create-profile-3-no-owner` and `create-profile-3-other-owner`: contract errors; `get-missing-profile-3`, `cancel-missing-profile-3`: a missing task is nobody's).

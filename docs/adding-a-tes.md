# Adding a TES

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

## One stack per worktree

Each worktree can run its own stack next to the others. Two variables, read by `make`, `scripts/test.sh`, compose and the harness (`harness/stack.py`), select it:

| Variable | Default (main checkout) | Effect |
|---|---|---|
| `TES_AUTHZ_PROJECT` | `tes-authz` | compose project, container names `<project>-opa`, `<project>-oidc`, …, network `<project>_default` |
| `TES_AUTHZ_PORT_BASE` | `18080` | host ports: OpenFGA base+0, OPA +101, OPA front +110, OpenFGA shim +111, stub +112, OIDC +113 (so the defaults are 18080, 18181, 18190–18193) |

`TES_AUTHZ_<NAME>_PORT` (e.g. `TES_AUTHZ_OIDC_PORT`) still moves a single port. Keep port bases at least 200 apart. Export both variables in the shell that runs `make` and pytest, so that `make test`, `make up`/`make down` and a direct `pytest` all address the same stack. `make down` and the cleanup in `make test` remove only that project's containers. The values for the phase-2 worktrees are in `PHASE2-STACKS.md`.

## Mock OIDC issuer

`oidc/issuer.py` serves the issuers `a` and `b` on port 18193 (loopback). Endpoints per issuer: discovery, `jwks`, `userinfo` (GET or POST), and a `token` endpoint that refuses every grant: tokens come from the control API (`POST /_control/tokens`, see the module docstring), so tests choose subject, claims, audience, expiry, scope, key and format directly. Every token, JWT or opaque, also works at userinfo until it expires; userinfo returns `sub` plus the claims given at minting.

Control API: mint tokens; rotate keys (with or without overlap) and retire keys from the JWKS; script userinfo per subject or by default (`mode: jwt` for a signed `application/jwt` answer, `status`, `delay`, `close`, a different `sub`, a different `content_type`); read recorded userinfo calls (token hashes, never tokens); reset. A TES never calls it.

The RSA code (`oidc/minijose.py`) is textbook PKCS #1 v1.5 in the standard library, so the container needs only the pinned Python image, like the shims. It is for tests only. `tests/test_oidc_jose.py` checks it against PyJWT with `cryptography` (a dev dependency) in both directions. Keys are generated at startup (about 1 s for two 2048-bit keys) and live in memory, so a restarted issuer has new keys.

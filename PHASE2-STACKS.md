# Phase-2 stacks: one per worktree

Each phase-2 worktree runs its own harness stack (engines, shims, stub, mock OIDC issuer), so the TES agents don't stop each other's containers. Set both variables in the shell that runs `make` and pytest, in that worktree only. See README, "One stack per worktree".

| Worktree | `TES_AUTHZ_PROJECT` | `TES_AUTHZ_PORT_BASE` | OpenFGA | OPA | OPA front | OpenFGA shim | stub | OIDC | Compose network | Issuer container |
|---|---|---|---|---|---|---|---|---|---|---|
| `service` (main) | `tes-authz` (default) | `18080` (default) | 18080 | 18181 | 18190 | 18191 | 18192 | 18193 | `tes-authz_default` | `tes-authz-oidc` |
| `service-tesk` | `tes-authz-tesk` | `18500` | 18500 | 18601 | 18610 | 18611 | 18612 | 18613 | `tes-authz-tesk_default` | `tes-authz-tesk-oidc` |
| `service-funnel` | `tes-authz-funnel` | `18700` | 18700 | 18801 | 18810 | 18811 | 18812 | 18813 | `tes-authz-funnel_default` | `tes-authz-funnel-oidc` |
| `service-tesp` | `tes-authz-tesp` | `18900` | 18900 | 19001 | 19010 | 19011 | 19012 | 19013 | `tes-authz-tesp_default` | `tes-authz-tesp-oidc` |

Bash (for example, TESP):

```sh
export TES_AUTHZ_PROJECT=tes-authz-tesp TES_AUTHZ_PORT_BASE=18900
make test                      # or: make up / pytest … / make down
```

Fish:

```fish
set -x TES_AUTHZ_PROJECT tes-authz-tesp; set -x TES_AUTHZ_PORT_BASE 18900
make test
```

Notes:

- Your TES's own containers keep their `tes-authz-<tes>-*` names, and their ports must stay outside the blocks above. `tes-authz-tesp-mongo` already uses 18303; the blocks avoid 18300–18499 for that reason.
- Containerised TESes join `<project>_default` and reach the services by service name (`Engine.network_url`), and the issuer at `harness.oidc.NETWORK_BASE` (`http://<project>-oidc:8080`). Both follow the project automatically.
- Kind clusters attach the issuer with `docker network connect kind "$TES_AUTHZ_PROJECT-oidc"` (README, "Add a TES").
- Never run `make test`, `make up` or `make down` without these variables in a phase-2 worktree: the defaults address the main checkout's stack.

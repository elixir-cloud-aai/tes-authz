# Getting started

Needs Docker with Compose, `uv` and `make`. Everything stays inside this folder: the virtual environment in `.venv/` and the uv cache in `.cache/`.

!!! warning "Local test setup only"

    This compose file is a local test and reference setup. All containers are read-only, drop all capabilities and run without new privileges, and ports bind to loopback only. But OPA's and OpenFGA's own APIs (18181, 18080) are published for the findings tests and are **not authenticated**: any local process can change policy data or tuples. A deployment publishes only the shims and enables OPA token authorization and OpenFGA preshared keys.

```sh
make test     # lint, types, `opa check`, start services, all suites, stop and remove
make up       # start only (ports 18080 OpenFGA, 18181 OPA, 18190 OPA front, 18191 OpenFGA shim, 18192 stub, 18193 OIDC)
make unit     # tests that need no containers
make lint     # ruff (lint and format check) and mypy
make down     # stop and remove containers and the state volume
```

`scripts/test.sh [pytest args]` is what `make test` runs. Set `TES_AUTHZ_KEEP=1` to leave the services running afterwards. Try an evaluation by hand with `make up`, then:

```sh
curl -s localhost:18190/access/v1/evaluation -d @<(jq .request golden/requests/create-member-subgroup.json)
```

To run a second stack next to this one (e.g. in another worktree), see [One stack per worktree](adding-a-tes.md#one-stack-per-worktree).

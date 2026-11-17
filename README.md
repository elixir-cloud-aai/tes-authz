# TES AuthZ: engine side (phase 1)

[![License][badge-license]][badge-url-license]
[![Build_status][badge-build-status]][badge-url-build-status]
[![Docs][badge-docs]][badge-url-docs]

Reference decision services, shims and a test harness for the TES AuthZ contract `tes-authzen/1`, as specified in `../spec.md` (draft 3). Phase 1 covers OPA and OpenFGA, with the harness the TES side plugs into (Poiesis first, then TESK, Funnel and TESP).

## Quick start

Needs Docker with Compose, `uv` and `make`:

```sh
make test     # lint, types, `opa check`, start services, all suites, stop and remove
make up       # start only (OPA front on 18190, OpenFGA shim on 18191, ...)
make down     # stop and remove containers and the state volume
```

The services are a local test setup: the engines' own APIs are published
unauthenticated. Read [Getting started][docs-getting-started] first.

## Documentation

The documentation is at <https://tes-authz.readthedocs.io> (sources in
[`docs/`](docs/)):

- [Getting started][docs-getting-started]: run the services and try an
  evaluation
- [Operators][docs-operators]: reference policy, OpenFGA mapping,
  deployment notes
- [Adding a TES][docs-adding-a-tes] and [adding an
  engine][docs-adding-an-engine]: adapters, the mock OIDC issuer, one
  stack per worktree
- [Testing][docs-testing]: test layers and golden requests
- [Findings][docs-findings]: spec claims checked against running software
- [Contributing][docs-contributing]: the development workflow

## Contributing

Contributions are welcome! See the [contributing
guide][docs-contributing] and mind our [code of conduct][code-of-conduct].

## License

[Apache License 2.0](LICENSE), copyright ELIXIR On-Cloud.

[badge-build-status]: <https://github.com/elixir-cloud-aai/tes-authz/actions/workflows/ci.yml/badge.svg?branch=dev>
[badge-license]: <https://img.shields.io/badge/license-Apache%202.0-blue.svg>
[badge-url-build-status]: <https://github.com/elixir-cloud-aai/tes-authz/actions/workflows/ci.yml?query=branch%3Adev>
[badge-url-license]: <https://www.apache.org/licenses/LICENSE-2.0>
[badge-docs]: <https://readthedocs.org/projects/tes-authz/badge/?version=latest>
[badge-url-docs]: <https://tes-authz.readthedocs.io/en/latest/?badge=latest>
[code-of-conduct]: <https://github.com/elixir-cloud-aai/.github/blob/main/CODE_OF_CONDUCT.md>
[docs-getting-started]: <https://tes-authz.readthedocs.io/en/latest/getting-started/>
[docs-operators]: <https://tes-authz.readthedocs.io/en/latest/operators/>
[docs-adding-a-tes]: <https://tes-authz.readthedocs.io/en/latest/adding-a-tes/>
[docs-adding-an-engine]: <https://tes-authz.readthedocs.io/en/latest/adding-an-engine/>
[docs-testing]: <https://tes-authz.readthedocs.io/en/latest/testing/>
[docs-findings]: <https://tes-authz.readthedocs.io/en/latest/findings/>
[docs-contributing]: <https://tes-authz.readthedocs.io/en/latest/contributing/>

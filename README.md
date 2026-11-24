# TES AuthZ: the `tes-authzen/1` specification

[![License][badge-license]][badge-url-license]
[![Build_status][badge-build-status]][badge-url-build-status]
[![Docs][badge-docs]][badge-url-docs]

**`tes-authzen/1`** is a specification for authorizing requests to GA4GH Task Execution Service (TES) implementations: a TES asks an external decision service, over [AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html), whether a caller may create, read, list or cancel tasks, so that access policy lives in one place instead of in every TES. The specification is a **draft** (draft 3, accepted for implementation on 2026-11-16): read it in [`spec/tes-authzen-1.md`](spec/tes-authzen-1.md) or on the [documentation site][docs-specification].

## The specification

A TES keeps authentication (OIDC), an owner stamped on every task, and a thin hook that asks one standard AuthZEN Access Evaluation per decision; everything that is policy lives in a decision service of the operator's choice. A TES returns, lists and cancels only the caller's own tasks, whatever the decision service answers (owner only; no admin views, sharing belongs in clients). Without configuration, every TES behaves as today. The specification covers:

- [§3 The contract](spec/tes-authzen-1.md#3-the-contract-authzen-mapping): subject, actions, the two resource types, context, list filtering, userinfo and the exact request shape
- [§4 Failure semantics, configuration, security](spec/tes-authzen-1.md#4-failure-semantics-configuration-security): status codes, configuration keys, startup checks
- [§5 Built-in claim rule and composition](spec/tes-authzen-1.md#5-built-in-claim-rule-and-composition): the optional admission gate, ANDed with the decision
- [§6 The hook](spec/tes-authzen-1.md#6-the-hook): pseudo-code and implementation notes for Poiesis, TESK, Funnel and TESP
- [§7 Reference decision service and engines](spec/tes-authzen-1.md#7-reference-decision-service-and-engines): the reference policy and how OPA, OpenFGA, Cedar, Casbin, Cerbos and Topaz plug in
- [§8 Test plan](spec/tes-authzen-1.md#8-test-plan): test layers and the shared conformance cases
- [§10 Decisions](spec/tes-authzen-1.md#10-decisions) and [§11 Open questions](spec/tes-authzen-1.md#11-open-questions)
- [§12 `tes-authzen/2`](spec/tes-authzen-1.md#12-tes-authzen2-delta-to-1): the extension Poiesis sends (authenticator, actor and API key properties, response context; task sharing marked as Poiesis extensions outside the contract)
- [§13 `tes-authzen/3`](spec/tes-authzen-1.md#13-tes-authzen3-delta-to-2): the current profile, without the task set `all`

## Reference tooling

Around the specification, this repository also holds **reference tooling**: decision services for OPA and OpenFGA behind the `tes-authzen/1` endpoint (they accept `tes-authzen/2` and `/3` too), the shims they need, and a conformance harness that TES implementations plug into (Poiesis first, then TESK, Funnel and TESP). They show that the specification works with real engines and TES implementations; read the specification first.

### Quick start

Needs Docker with Compose, `uv` and `make`:

```sh
make test     # lint, types, `opa check`, start services, all suites, stop and remove
make up       # start only (OPA front on 18190, OpenFGA shim on 18191, ...)
make down     # stop and remove containers and the state volume
make kubernetes  # deploy deploy/kubernetes/ to the current kubectl context (e.g. kind) and test it
```

The services are a local test setup: the engines' own APIs are published
unauthenticated. Read [Getting started][docs-getting-started] first. To
run the OPA decision service on Kubernetes, see [Operators][docs-operators]
(`deploy/kubernetes/`).

## Documentation

The documentation is at <https://tes-authz.readthedocs.io> (sources in
[`docs/`](docs/)):

- [Specification][docs-specification]: the `tes-authzen/1` specification itself (draft 3)
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
[docs-specification]: <https://tes-authz.readthedocs.io/en/latest/specification/>
[docs-getting-started]: <https://tes-authz.readthedocs.io/en/latest/getting-started/>
[docs-operators]: <https://tes-authz.readthedocs.io/en/latest/operators/>
[docs-adding-a-tes]: <https://tes-authz.readthedocs.io/en/latest/adding-a-tes/>
[docs-adding-an-engine]: <https://tes-authz.readthedocs.io/en/latest/adding-an-engine/>
[docs-testing]: <https://tes-authz.readthedocs.io/en/latest/testing/>
[docs-findings]: <https://tes-authz.readthedocs.io/en/latest/findings/>
[docs-contributing]: <https://tes-authz.readthedocs.io/en/latest/contributing/>

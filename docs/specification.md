# Specification

`tes-authzen/1` is the contract between a GA4GH Task Execution Service (TES) and an external decision service: how the TES authenticates callers, which AuthZEN 1.0 evaluation requests it sends for creating, reading, listing and cancelling tasks, and how it acts on the decisions. The decision services, shims and harness in this repository are reference tooling for it.

!!! note "Draft"

    The specification is a draft (draft 3). It is currently kept outside this repository (`../spec.md`) and moves in, as the source of this page, with [#7](https://github.com/elixir-cloud-aai/tes-authz/issues/7).

# Adding an engine

1. Add a compose service for the engine, plus a shim if it has no AuthZEN endpoint or needs a mapping. A shim is `common.serve(port, decide, metadata)` with one `decide(request, headers) -> bool`. Reuse `common` for validation, claim normalisation, prefix expansion and identifier encoding.
2. Configure the engine from `config/reference-policy.json`: load it as data, or generate the engine's artefacts from it as `engines/openfga/setup.py` does.
3. Add one `Engine` entry to `harness/engines.py` with its host URL (and its compose-network URL).

The replay (all golden cases), the smoke tests and every TES adapter then pick it up. If the engine's answers differ from the expected decisions, fix the engine-side policy, not the expectations: the expected table is shared by all engines.

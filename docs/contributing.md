# Contributing

Contributions are welcome! See the organisation's [contributing
guide][contributing] and mind our [code of conduct][code-of-conduct].

- Branch from `dev` and open pull requests against it. Pull request titles
  follow [Conventional Commits](https://www.conventionalcommits.org/) and have
  at most 50 characters (checked in CI), as they become the commit messages of
  squash merges.
- Install the dependencies with `uv sync`, then the commit hooks with `uv run
  pre-commit install` (they run ruff, mypy and ast-grep from `.venv`, plus
  semgrep, gitleaks on the staged changes and actionlint). The hook
  environments live in `~/.cache/pre-commit`, outside the checkout.
- CI (the gate `CI passed` must pass) runs these checks; to run them all
  locally:

  ```sh
  uv lock --check                       # lock matches pyproject.toml
  make lint                             # ruff and mypy
  uv run pre-commit run --all-files     # all hooks on all files (incl. the project rules below)
  uv run pre-commit run --all-files --hook-stage manual gitleaks-all  # secrets in the whole checkout
  make unit                             # tests without containers
  make test                             # everything, with the services (needs Docker; pulls the images of compose.yaml)
  make kubernetes                       # deploy/kubernetes/ on the current kubectl context (needs a disposable cluster, e.g. kind)
  make image                            # build the image of Dockerfile and test a container of it (needs Docker)
  uv run --isolated --only-group docs mkdocs build --strict  # these docs (leaves .venv as is); fails on warnings
  ```

- Documentation lives in `docs/` (MkDocs Material, `mkdocs.yml`), published
  on Read the Docs from `.readthedocs.yaml`. Changes to behaviour,
  configuration or the workflow update the docs in the same pull request.

## Releases

A release publishes the [container image](image.md) (OPA, the front and the
policy of the tagged commit) and creates the GitHub release; the
specification and the rest of the tooling are versioned with it. Releases
come from `dev` (`.github/workflows/release.yml`), as pre-releases until
1.0.0:

1. A release-prep pull request sets the version in `pyproject.toml` and the
   version and `date-released` in `CITATION.cff`, and adds the curated
   notes `docs/releases/<version>.md` (in the organisation's format; add
   them to the `nav` of `mkdocs.yml`, or the strict docs build fails).
2. Once it is merged and CI passed for the push to `dev`, a maintainer tags
   the merge commit with a signed, annotated tag `v<version>` and pushes
   it.
3. The workflow checks the tag, the commit, the versions and the notes,
   then builds the image and pushes it by digest, scans it (Trivy; fixable
   critical and high findings fail the release, `.trivyignore.yaml` lists
   the accepted ones), signs it, attests it and tags it `<version>`, and
   creates the GitHub release. Pushing and tagging the image need approval
   in the `release` environment.

Released images and tags don't change: if a release fails after the image
was tagged, release a new patch version. To test the workflow in a fork,
set the fork's repository variable `DOCKERHUB_ORG` to a Docker Hub
organisation of your own first (the image goes to `elixircloud`
otherwise).

## Project rules

Beyond ruff (including its bandit rules, `S`), [semgrep](https://semgrep.dev/)
and [ast-grep](https://ast-grep.github.io/) check hazards specific to this
code base. Both run as pre-commit hooks, so on commit and in CI (`Lint`).

| Tool | Rule | Flags | Where |
|---|---|---|---|
| semgrep | `urlopen-without-timeout` | `urllib.request.urlopen()`, openers of `build_opener()` and `http.client` connections without a timeout, or with a timeout of `None` (a hanging engine or issuer would block the caller instead of failing closed) | everywhere |
| semgrep | `request-body-unbounded` | `self.rfile.read()` of a request body without a preceding comparison of its length with a maximum, or guarded only by a comparison with a number (`if length > 0:`); negative lengths are left to review | everywhere |
| semgrep | `credentials-or-subject-logged` | the `Authorization` header, values named as tokens (`token`, `auth_token`, `jwt`, `bearer`, ...), or the subject of an AuthZEN request (ID and claims) reaching a log call, `print()`, `sys.stderr.write()` or a handler's `log_message()`/`log_error()`; `hash_id()` sanitises (`encode_id()` keeps plain IDs, so it doesn't) | everywhere |
| semgrep | `yaml-unsafe-load` | PyYAML's full and unsafe loaders (shared with FOCA and trs-filer) | everywhere |
| ast-grep | `shim-policy-decision` | comparisons, `match` cases and `startswith()`/`endswith()` tests with action names, resource types or task set IDs (as literals, or `ACTIONS`, `RESOURCE_TYPES`, `TASK_SET_IDS`): shims translate, the engines decide | `shims/` except `common.py` |
| ast-grep | `fail-open-except` | `except` and `finally` blocks that allow: `return True` (also in a tuple), `True` assigned to or passed as `decision`, `allow`, `allowed` or `result` | `shims/`, `stub/`, `tes/mock/`, `oidc/` |
| ast-grep | `decision-truthiness` | an engine's `decision` or `result` (lookups, or `decision`, `result`, `allowed` variables) read with `bool()`, `if`/`elif`/`while`, a conditional expression, `== True`, `!= False`, `is not False`, `and` or `or`, or denied only for `== False`/`is False` (only a boolean `true` allows) | `shims/`, `tes/mock/` |
| ast-grep | `unverified-token-claims` | `decode_unverified()` (also imported under another name), `jwt.get_unverified_header()`, `jwt.decode()` with `verify_signature` or `verify` false, and PyJWT's decoders imported by name | everywhere except `oidc/minijose.py` and tests |
| ast-grep | `root-logger-call` | messages logged with the root logger (`logging.info()`, `logging.root`, `getLogger()` without a name or with `"root"`, functions imported from `logging`) | everywhere |

The rules live in `.semgrep/tes-authz.yml` and `.ast-grep/rules/`
(`sgconfig.yml`), with their tests in `.semgrep/tes-authz.py` and
`.ast-grep/rule-tests/` (they contain findings on purpose, so the semgrep scan
and Sourcery skip them). Add a rule together with test cases that it must and
must not flag, and run them:

```sh
uv run pre-commit run semgrep-test --all-files   # semgrep rule tests
uv run ast-grep test --skip-snapshot-tests       # ast-grep rule tests
uv run ast-grep scan                             # the ast-grep rules on the code
```

Suppress a finding only if it is a false positive or can't be avoided, with
a comment that gives the reason: `# ast-grep-ignore: <rule>` on the line
before the finding, `# nosemgrep: <rule>` on its first line. The rules
are syntactic and catch the common forms; their notes in the rule files say
what they don't detect.

[code-of-conduct]: <https://github.com/elixir-cloud-aai/.github/blob/main/CODE_OF_CONDUCT.md>
[contributing]: <https://github.com/elixir-cloud-aai/.github/blob/main/CONTRIBUTING.md>

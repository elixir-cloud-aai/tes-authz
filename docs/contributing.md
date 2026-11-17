# Contributing

Contributions are welcome! See the organisation's [contributing
guide][contributing] and mind our [code of conduct][code-of-conduct].

- Branch from `dev` and open pull requests against it. Pull request titles
  follow [Conventional Commits](https://www.conventionalcommits.org/) and have
  at most 50 characters (checked in CI), as they become the commit messages of
  squash merges.
- Install the dependencies with `uv sync`, then the commit hooks with `uv run
  pre-commit install` (they run ruff and mypy from `.venv`, plus gitleaks on
  the staged changes and actionlint). The hook environments live in
  `~/.cache/pre-commit`, outside the checkout.
- CI (the gate `CI passed` must pass) runs these checks; to run them all
  locally:

  ```sh
  uv lock --check                       # lock matches pyproject.toml
  make lint                             # ruff and mypy
  uv run pre-commit run --all-files     # all hooks on all files
  uv run pre-commit run --all-files --hook-stage manual gitleaks-all  # secrets in the whole checkout
  make unit                             # tests without containers
  make test                             # everything, with the services (needs Docker; pulls the images of compose.yaml)
  uv sync --group docs && uv run mkdocs build --strict  # these docs; fails on warnings
  ```

- Documentation lives in `docs/` (MkDocs Material, `mkdocs.yml`), published
  on Read the Docs from `.readthedocs.yaml`. Changes to behaviour,
  configuration or the workflow update the docs in the same pull request.

[code-of-conduct]: <https://github.com/elixir-cloud-aai/.github/blob/main/CODE_OF_CONDUCT.md>
[contributing]: <https://github.com/elixir-cloud-aai/.github/blob/main/CONTRIBUTING.md>

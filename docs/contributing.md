# Contributing

## Setup

```bash
git clone https://github.com/mrbrownnn/DevForge.git
cd DevForge
pip install -e ".[dev]"
python -m pytest -q
```

Python 3.11+. Dependencies are deliberately few: pydantic, typer, PyYAML, rich.
Adding one needs a reason in the pull request.

## Checks

```bash
python -m pytest -q            # must be green, no network, no paid API calls
ruff check .
ruff format --check .
```

Tests must never call a real model runtime. `MockAgentRuntime` exists so the whole
harness can be exercised deterministically and for free; the Claude Code adapter is
tested through `parse_result` and `build_argv`, which need no subprocess.

## What CI runs

`.github/workflows/ci.yml`, on every push and pull request. Every job here can be
run locally, and the ones that catch the most are the ones that are hardest to run
locally — which is the point of running them here.

| Job | What it would catch |
| --- | --- |
| `lint` | `ruff check .` |
| `test` | The suite on 3 OSes x 3 interpreters, with the optional extras installed |
| `degraded` | The suite on a bare install: every "not available, and here is why" branch |
| `coverage` | Coverage as an artefact. It does not gate — a threshold buys tests written to move a number |
| `security` | DevForge's own scanner, audit, SBOM and report against DevForge's own tree, plus expired baseline acceptances |
| `assets` | Every shipped YAML/JSON parses, and the builtin workflows, agents, runtimes, skills, registry, radar and eval catalogues all load |
| `package` | The wheel builds, passes `twine check`, and actually contains its builtin assets and the licence |
| `smoke` | That wheel installed on each OS and driven across the whole CLI surface from a directory that is not the source tree |
| `ci-ok` | One name to require in a branch rule, so the rule survives a matrix change |

`.github/workflows/release.yml` is the release path: tag `vX.Y.Z` builds, checks the
tag against the packaged version, re-runs the smoke on every OS and interpreter
against the release candidate, and only then creates the GitHub release. Publishing
to PyPI uses trusted publishing and stays skipped until the repository variable
`PYPI_TRUSTED_PUBLISHING` is set to `true`. Running it from the Actions tab exercises
everything except the two publishing steps, so the path is never first tried on the
day of a release.

## DragonBot

`.github/workflows/dragonbot.yml` replaces Dependabot. It does the same monthly
job, with one difference that is the whole reason it exists: it opens its pull
requests as a GitHub App this repository owns, so they carry this project's own
bot identity and avatar rather than a shared one.

What it does, once a month and on demand:

- **Action versions** are rewritten in the branch, `@vN` refs only. A branch ref
  such as `pypa/gh-action-pypi-publish@release/v1` is how that action asks to be
  pinned, so it is left alone. CI on the pull request is what says whether a bump
  is safe.
- **Dependency floors** are reported, never rewritten. The specifiers in
  `pyproject.toml` are floors, not pins: raising one narrows what a user is
  allowed to install, and that is a decision with a reason behind it rather than
  a chore to automate.

### Setting it up

The job skips itself until this is done, so an unconfigured fork stays green.

1. Create a GitHub App owned by this account. Name it **DragonBot** and give it
   the avatar you want its pull requests to carry.
2. Repository permissions: **Contents** read & write, **Pull requests** read &
   write. Nothing else - no account permissions, no webhook.
3. Install the App on this repository.
4. Add repository variable `DRAGONBOT_APP_ID` (the App's ID) and repository
   secret `DRAGONBOT_PRIVATE_KEY` (the generated `.pem`, whole file including the
   header and footer lines).

The App's name and avatar are what appear on the pull request. Changing either
later changes it everywhere, with no change to this workflow.

## Where things go

| Change | Location |
| --- | --- |
| New workflow / skill / agent | `src/devforge/builtin/…` (or your own project dirs) |
| New tool | `src/devforge/tools/`, registered in `ToolRegistry.default()` |
| New verifier kind | `src/devforge/verification/`, registered in `VerifierRegistry.default()` |
| New runtime | `src/devforge/runtime/`, registered in `RuntimeRegistry.default()` |
| Anything vendor-specific | a runtime adapter, never `core/` |

`core/` must not import a concrete runtime, tool or verifier. If a change makes that
necessary, the interface is wrong.

## Style

- Type annotations everywhere; pydantic models for anything crossing a boundary or
  hitting disk.
- Comments explain *why*, not what. Prefer none to a restatement of the code.
- Errors are values where the caller can act on them (`ToolResult.status`,
  `VerificationResult.status`) and exceptions where they cannot.
- New capabilities that are not actually implemented must report `unavailable`. Never
  return plausible-looking fake data, and never let a missing capability read as a pass.

## Tests

Every change needs a test that would fail without it. Cover the failure path, not only
the happy one — most of this codebase exists to handle failure.

Fixtures: `project` (an initialised `ProjectStore` in a tmp dir) and `task`, in
`tests/conftest.py`. Async tests need no decorator; `asyncio_mode = "auto"`.

## Commits

Conventional Commits, small and coherent, one concern each:

```
feat(verification): add coverage verifier kind
fix(policy): reject symlinked paths outside the workspace
docs(security): state the sandbox limitation explicitly
test: cover approval rejection path
```

Do not include tooling or agent attribution in commit messages.

## Pull requests

State what changed, why, and what you verified. If a limitation remains, say so in the
PR and in the README — an honest gap is a feature of this project.

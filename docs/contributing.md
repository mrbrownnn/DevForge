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

DragonBot is this repository's own bot, and it does two jobs: it keeps
dependencies honest, and it reviews every pull request. Both are CI - workflows in
`.github/`, nothing in `src/devforge/` - and both run as a GitHub App this
repository owns, so its pull requests and comments carry this project's identity
and avatar rather than a shared one.

### Dependency updates

`.github/workflows/dragonbot.yml` replaces Dependabot. What it does, once a month
and on demand:

- **Action versions** are rewritten in the branch, `@vN` refs only. A branch ref
  such as `pypa/gh-action-pypi-publish@release/v1` is how that action asks to be
  pinned, so it is left alone. CI on the pull request is what says whether a bump
  is safe.
- **Dependency floors** are reported, never rewritten. The specifiers in
  `pyproject.toml` are floors, not pins: raising one narrows what a user is
  allowed to install, and that is a decision with a reason behind it rather than
  a chore to automate.

### Reviewing pull requests

`.github/workflows/dragonbot-review.yml` runs on every pull request that is not a
draft - opened, reopened, pushed to, or marked ready - and posts one comment that
it edits in place on each push. The reviewer itself is
`.github/dragonbot/review.py`, with `.github/dragonbot/test_review.py` beside it.

The comment has three kinds of note, kept apart because they are not equally
trustworthy:

| source | what it is | how it is wrong |
| --- | --- | --- |
| `diff rule` | patterns over the added lines and over the shape of the diff | false positives, and blind to anything it has no pattern for |
| `security scan` | `devforge security scan --json`, restricted to the files the pull request touches | the scanner's own limits: no vulnerability database, no taint analysis |
| `model` | an optional narrative pass | unreproducible, and confidently wrong often enough that it never sets the verdict |

Four things about it are deliberate:

- **It is a script, not a feature.** The reviewer depends on nothing but the
  standard library and is not importable from the package. It reviews this
  repository's pull requests; it is not a capability DevForge offers its users, and
  changing it cannot break an install.
- **It never fails the run.** Findings are reported, not enforced (`--fail-on high`
  exists and is not used). The `security (self-scan)` job in `ci.yml` is what gates
  a merge, and a review bot that can block one is a review bot people turn off.
- **It costs nothing.** The narrative section uses GitHub Models through the
  workflow's own `GITHUB_TOKEN`, which is what the `models: read` permission in
  that file is for. There is no API key to add. If the account has no Models
  access the request fails, the comment says that section was skipped, and every
  other finding still posts. If a runner ever rejects the `models: read` key,
  delete those two lines - the same skip path covers it. To use a paid provider
  instead, set `DEVFORGE_REVIEW_ENDPOINT`, `DEVFORGE_REVIEW_TOKEN` and
  `DEVFORGE_REVIEW_MODEL`; `GITHUB_TOKEN` is never forwarded to another host.
- **Nothing from the pull request reaches a shell.** A title or description on a
  fork's pull request is attacker-controlled text, so both are passed through the
  environment and a file rather than interpolated into a `run:` block. The diff is
  redacted and fenced as data before any of it is sent to a model.

The review never approves. The strongest sentence it can produce is "nothing
blocking was found", which is a statement about which checks ran, and a check that
did not run is printed as skipped rather than left out - an empty section and an
absent one look nothing alike.

On a pull request from a fork the job token is read-only: the review still runs and
appears in the run summary, and only the comment is skipped.

### Setting it up

Neither job needs this to run - the review posts as `github-actions[bot]`, and the
dependency job skips itself - so an unconfigured fork stays green. What it buys is
the identity.

1. Create a GitHub App owned by this account. Name it **DragonBot** and give it
   the avatar you want its pull requests to carry.
2. Repository permissions: **Contents** read & write, **Pull requests** read &
   write. Nothing else - no account permissions, no webhook.
3. Install the App on this repository.
4. Add repository variable `DRAGONBOT_APP_ID` (the App's ID) and repository
   secret `DRAGONBOT_PRIVATE_KEY` (the generated `.pem`, whole file including the
   header and footer lines).

The App's name and avatar are what appear on the pull requests it opens and the
reviews it posts. Changing either later changes it everywhere, with no change to
these workflows.

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

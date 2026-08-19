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

# Skills

A skill is reusable agent knowledge: Markdown with a YAML frontmatter header. Skills
are composed into the prompt of an agent at invocation time, so instructions live in
files rather than in Python.

Resolution order: `./.devforge/skills/` → `./skills/` → built-in. Files are discovered
as `<dir>/<name>/SKILL.md` (preferred) or `<dir>/<name>.md`.

## Format

```markdown
---
name: testing                       # defaults to the directory name
version: 1.0.0
description: Write tests that would fail without the change.
capabilities: [unit-testing, regression-testing]
dependencies: [debugging]           # resolved transitively, cycles detected
compatible_runtimes: ["*"]          # or a list of runtime names
---

# Testing

Everything below the frontmatter is handed to the agent verbatim.
```

## Resolution

`SkillRegistry.resolve(["architecture"])` returns `[requirements, planning,
architecture]` — dependencies first, each included once. A cycle raises `ConfigError`
naming the path. A skill whose `compatible_runtimes` excludes the active runtime is
rejected rather than silently dropped.

`devforge doctor` reports skills whose declared dependencies do not resolve, and agents
that reference skills which do not exist.

## Built-in skills

`requirements`, `planning`, `architecture`, `backend`, `frontend`, `testing`,
`debugging`, `security`.

They share a shape: a short method section, then anti-patterns. They are written as
instructions to an engineer, not as descriptions of a topic — an agent acts on the
former and ignores the latter.

## Adding one

Create `skills/performance/SKILL.md`:

```markdown
---
name: performance
version: 1.0.0
description: Diagnose and fix performance problems with measurements.
capabilities: [profiling, benchmarking]
dependencies: [debugging]
---

# Performance

1. Measure before changing anything. A profile, not a guess.
2. Fix the largest cost first; stop when the budget is met.
3. Prove the improvement with the same measurement.
```

Then `devforge skills` lists it, and any workflow step or agent spec can reference it
with `skills: [performance]`.

## How a skill reaches the model

`agents/prompt.py` composes: system prompt (from the agent spec) + the rendered prompt
template, which includes the full text of every resolved skill, the project memory from
`.devforge/*.md`, the step description, and — on a repair attempt — the diagnostics from
the failed verifiers. Templates use `{{placeholder}}` substitution, so prose containing
braces never breaks rendering.

# Coding assistants

DevForge ships engineering skills - how this project expects testing, debugging,
architecture and security work to be done. Those skills are useful to whatever
assistant you already use, not only to the agents DevForge drives itself.

`devforge init --ai <assistant>` writes them where that assistant reads them.

```
devforge assistants                    what is supported, and how sure we are
devforge init --ai cursor              install into this project
devforge init --ai all                 install for every assistant
devforge init --ai claude --global     install into your home directory
devforge init --ai cursor --force      replace files that already exist
devforge init --ai cursor --dry-run    show what would be written, write nothing
devforge versions                      what this install contains
devforge update --global               refresh globally installed files
```

## Supported assistants

Thirteen profiles, plus the `all` selector.

| id | assistant | writes to | layout |
| --- | --- | --- | --- |
| `claude` | Claude Code | `.claude/skills/` | established |
| `cursor` | Cursor | `.cursor/rules/*.mdc` | established |
| `windsurf` | Windsurf | `.windsurf/rules/` | established |
| `copilot` | GitHub Copilot | `.github/copilot-instructions.md` | established |
| `gemini` | Gemini CLI | `GEMINI.md` | established |
| `opencode` | OpenCode | `AGENTS.md` | established |
| `roocode` | Roo Code | `.roo/rules/` | established |
| `universal` | Universal / Agent Standard | `.agents/skills/` | established |
| `antigravity` | Antigravity | `.antigravity/rules/` | **inferred** |
| `codex` | Codex | `.codex/skills/` | **inferred** |
| `kiro` | Kiro | `.kiro/steering/` | **inferred** |
| `qoder` | Qoder | `.qoder/rules/` | **inferred** |
| `trae` | Trae | `.trae/rules/` | **inferred** |

**"Inferred" means the path follows convention but was not confirmed against that
assistant's documentation.** The installer says so when it writes one, because a file
written to a path the assistant does not read is silently ignored and looks exactly
like DevForge having done nothing. If one is wrong, correct the YAML - see below.

## Profiles are data

Every assistant is a file in `builtin/assistants/`. Adding one means adding a YAML
file; no Python changes, and no new tests.

```yaml
id: cursor
name: Cursor
confidence: established
target:
  path: .cursor/rules
  format: rules          # skill | rules | markdown
  filename: "devforge-{skill}.mdc"
  instructions: devforge.mdc
global_target:
  path: .cursor/rules
  format: rules
  filename: "devforge-{skill}.mdc"
```

Two reasons it is built this way. Thirteen classes differing only by a path and a
frontmatter style would be an abstraction with no content - the same reasoning that
made agents and workflows YAML. And `tests/test_architecture.py` forbids naming a
vendor anywhere in the source outside its adapter, so the names have to live in data
for the rule to survive.

Drop a file in `.devforge/assistants/` to override a built-in profile for one
project. Project files win, exactly as they do for workflows and agents.

### Formats

| format | shape | used by |
| --- | --- | --- |
| `skill` | markdown with `name`/`description` frontmatter | skill-directory assistants |
| `rules` | markdown with `description`/`globs`/`alwaysApply` | rule-file assistants |
| `markdown` | plain markdown, frontmatter stripped | everything else |

A target with a `filename` gets one file per skill plus an instructions file. A
target without one is a single file, and every skill is concatenated into it with
its headings demoted so the result has one outline rather than nine.

## What gets installed

One file per skill, plus an instructions file describing **the harness** rather than
coding in general - the assistant already knows how to write code, and what it does
not know is that this project verifies by execution, gates destructive operations
behind a human, and will falsify the patch afterwards.

Every generated file carries a marker comment, so a later run can tell its own
output from something you wrote by hand.

## The flags

**`--force`** replaces files that already exist. Without it an existing file is left
alone and reported as skipped: your hand-written rules file is not DevForge's to
overwrite.

**`--global`** installs into your home directory instead of a project. Assistants
whose profile declares no documented global location are skipped with a reason
rather than having one guessed for them.

**`--offline`** is accepted and is always true. DevForge imports no HTTP client - an
architecture test enforces it - so every install already uses bundled templates. The
flag exists for compatibility with toolchains that need it, and the command says so
rather than implying it did something.

**`--dry-run`** reports what would be written and writes nothing.

## `versions` and `update`

`devforge versions` lists what *this* install contains: workflows, agents, skills and
assistant profiles. It is not a list of available releases - with no network there is
no release index to read, and inventing one would be a lie about where the numbers
came from.

`devforge update` without `--global` refuses, and says why: DevForge cannot fetch a
release, so upgrading the CLI is a package-manager operation. `devforge update
--global` does the part that is actually possible - regenerating globally installed
assistant files from the package you now have.

## Limits

- Installing files does **not** make an assistant able to drive DevForge's workflow
  engine. It gives the assistant the same guidance; running workflows is still
  `devforge run`, and the only runtime adapter that executes agents is the one in
  `runtime/`.
- Five layouts are inferred rather than confirmed. Check them before relying on them.
- A single-file profile is regenerated wholesale by `--force`. Keep hand-written
  guidance in a separate file.

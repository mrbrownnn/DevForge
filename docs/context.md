# Context engineering

An agent that gets the whole repository gets a worse prompt than one that gets the
right ten files. DevForge builds a structural index, retrieves against the task, and
hands the agent a **context pack** it can audit before anything runs.

## The index

`devforge index` walks the project and records structure: files, their role (source,
test, config, docs, schema), the symbols they define with line numbers and signatures,
what they import, and who imports them.

**It stores no file contents.** Symbols carry names, kinds, lines and the first line of
a docstring - enough to judge relevance, not a copy of the source. An index that stored
excerpts would be a second copy of the repository with none of its access controls,
outliving the files it copied. Reading is always a fresh, policy-checked read.

Python is parsed with the standard library's `ast`. Other languages get a shallow regex
pass that finds top-level declarations and imports, so a JavaScript file yields worse
symbols than a Python one and retrieval there leans more on paths and terms.
Tree-sitter is the obvious upgrade; the seam is `extract_symbols`.

## Retrieval

Lexical and structural. **No vector database, no embedding model, no extra service** -
three properties that matter more here than raw recall: explainable (every result
carries its reasons), deterministic (same task, same pack), and free.

Signals, strongest first: exact symbol name, structural terms (path, symbol names,
imports), prose terms (docstrings, headings - weighted lower), role fit, and import
proximity, which surfaces the caller you forgot.

Prose weighs less than structure for a concrete reason: a module whose docstring reads
*"unrelated to authentication"* mentions the word without being about it, and lexical
retrieval cannot tell those apart. Ranking structure above prose keeps that file out of
the top results without pretending the ambiguity does not exist.

### When nothing matches

Retrieval reports low confidence rather than listing the least-irrelevant files, and
the caveat goes into the pack directly under the task. An agent treats anything listed
as relevant, so a weak list is worse than an empty one with an explanation.

Confidence is relative to the corpus - whether the top result stands out from the rest -
because a fixed threshold would call every small project unmatched.

## The context pack

```bash
devforge context "Change JWT authentication"           # inspect it
devforge context "Change JWT authentication" --prompt  # exactly what the agent sees
devforge context "Change JWT authentication" --compare # measure it
```

Sections: task, project summary, relevant files (with scores and reasons), relevant
symbols, dependencies, architecture, constraints, previous decisions, tests, known
issues, and what was withheld.

The orchestrator builds a pack per step and puts it where the whole-memory dump used to
go. With no index, it falls back to project memory exactly as before - a missing index
is not an error.

## Measured

On a 64-file fixture, with real `tiktoken` counts:

| Context | Tokens | Files |
| --- | --- | --- |
| Full repository | 4,369 | 64 |
| Retrieved pack | 515 | 3 |

**88.2% fewer tokens, precision 1.00, recall 0.75**, pack built in ~16ms.

`tests/test_context.py` asserts these thresholds. What it deliberately does **not**
measure is task success against a real model: the mock runtime succeeds
deterministically regardless of context quality, so any such number would be an
artefact of the mock rather than evidence about a model. A test exists to say so.

## Memory

Project memory lives in `.devforge/`: `context.md`, `architecture.md`, `decisions.md`,
`conventions.md`, `known-issues.md`. Files, not a database.

Cross-project leakage is prevented structurally rather than by filtering: memory is read
from the project's own directory, and the index records the root it was built from and
is **refused** if loaded against a different one.

## Secrets are never indexed

Three layers: ignore patterns (build output, caches - noise control, not security),
sensitive paths (`.env`, `*.pem`, `**/secrets/**`, `~/.ssh` - refused before opening),
and a content check that refuses files which *are* credential material - a real private
key block, or a run of secret-shaped assignments as in a misnamed `.env`.

**Mention is not material.** An earlier version excluded any file whose content tripped
secret detection, which dropped this project's own `redaction.py`, `policy/network.py`
and every security test - so an agent asked to fix secret handling would have received
context with the secret handling missing. Files that discuss credentials are indexed;
files that are credentials are not. Exclusions are counted and named; the matched text
is never recorded.

## Keeping it fresh

`devforge context-doctor` re-hashes every indexed file and reports drift. A stale index
is worse than none: it produces confident, wrong context. Re-index after significant
changes; `devforge index` is incremental and skips unchanged files by hash.

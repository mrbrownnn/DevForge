# CLI reference

Every command below is available once DevForge is installed. Commands that read or
write project state need a DevForge project — run `devforge init` first.

Exit codes: `0` success, `1` failure, `2` paused awaiting approval.
Every command supports `--json` for machine-readable output.

| Command | Purpose |
| --- | --- |
| `devforge init [path]` | Create `.devforge/` project state (`--ai <assistant>` also installs skills for it) |
| `devforge assistants` | Coding assistants DevForge can install its skills into |
| `devforge versions` | What this install contains: workflows, agents, skills, assistants |
| `devforge update --global` | Refresh globally installed assistant files |
| `devforge plan -w feature` | Show what a workflow would do; run nothing |
| `devforge run -w feature -t "..."` | Execute a workflow (`--resume`, `--interactive`, `--events`) |
| `devforge status [task]` | Run state; `--all` lists runs, `--json` for machines |
| `devforge review [task]` | Agent output, artifacts and verification per step |
| `devforge verify` | Run verifiers against the working tree, outside a run |
| `devforge approve --gate G` | Approve or `--reject` a pending gate |
| `devforge skills` | List discoverable skills |
| `devforge workflows` | List available workflows |
| `devforge runtimes` | List agent runtimes and their availability (6 providers, profile-driven) |
| `devforge doctor` | Environment check: what works, what is unavailable |
| `devforge bench` | Repair success rate against the seeded-defect benchmark (`--solver reference\|cheat\|none`) |
| `devforge index` | Build the codebase index (structure only, no file contents) |
| `devforge context "task"` | Show the context pack an agent would receive (`--compare` measures it) |
| `devforge context-doctor` | Report whether the index still matches the working tree |
| `devforge registry list` | Third-party skill sources, pins and dispositions |
| `devforge registry show <id>` | Recorded evidence and decision for one source |
| `devforge registry verify` | Validate the registry: pins, licenses, trust decisions |
| `devforge inspect-skill <dir>` | Statically inspect a local skill directory; nothing is executed |
| `devforge skill search <query>` | Search the catalogue of third-party skills (offline) |
| `devforge skill audit <name>` | Fetch at the pin and inspect; installs nothing |
| `devforge skill install <name>` | Fetch, verify, gate, install, lock |
| `devforge skill update <name>` | Move a pin deliberately and re-audit |
| `devforge skill remove <name>` | Remove an installed skill and its lock entry |
| `devforge skill list` | List installed skills (`--verify` re-hashes them) |
| `devforge security scan` | Scan a workspace for secrets, injection-shaped text and dangerous code |
| `devforge security audit` | Check whether the declared security controls are actually in place |
| `devforge security sbom` | CycloneDX inventory: packages, skills, MCP servers, runtime binaries |
| `devforge security threats` | The threat model and the defence-in-depth layers |
| `devforge security report` | Full report: audit, scan, inventory and residual risk |
| `devforge eval run` | Measure one configuration against the benchmark cases |
| `devforge eval compare` | Two reports side by side; names differences, never a winner |
| `devforge eval report` | Render a saved evaluation report as Markdown |
| `devforge eval cases` | The benchmark cases that apply here |
| `devforge eval configs` | The evaluation configurations that apply here |
| `devforge falsify` | Search adversarially for counterexamples against the current patch |
| `devforge falsify report` | Show a persisted falsification report |
| `devforge falsify explain <id>` | Explain one finding, with `--regression` to print a test |
| `devforge falsify list` | Persisted falsification runs, newest first |
| `devforge falsify corpus` | Counterexamples preserved across runs |
| `devforge git worktree` | Create, list and remove isolated worktrees |
| `devforge git commit` | Plan a commit, screen its contents, then record it |
| `devforge git pr` | Write the pull-request artifact (does not push) |
| `devforge git guard` | Say what would happen to a git command, without running it |
| `devforge continuous detect` | Scan for engineering work nobody has filed yet |
| `devforge continuous propose` | Record findings as proposals in the backlog |
| `devforge continuous backlog` | Proposals and what happened to them |
| `devforge continuous approve` | Agree that a proposal is worth doing |
| `devforge continuous execute` | Prepare an approved proposal in an isolated worktree |
| `devforge continuous verify` | Re-detect and check the findings stopped firing |
| `devforge platform worker` | Register, list and revoke execution workers |
| `devforge platform submit` | Queue a task for a worker |
| `devforge platform dispatch` | Lease, execute and independently verify a task |
| `devforge platform approve` | Decide a gate a worker paused at |
| `devforge platform status` | The queue, workers and audit health |
| `devforge platform audit` | Read the hash-chained audit trail and check it |
| `devforge skill radar` | Sweep watched sources: NEW, UPDATE, WARNING, DEPRECATE |
| `devforge skill outdated` | Installed skills a sweep found a newer version of |
| `devforge skill audit-all` | Re-inspect every installed skill and detect content drift |
| `devforge skill recommend` | Candidates worth a person's review, best first |

Exit codes: `0` success, `1` failure, `2` paused awaiting approval.

supports `--json`.

---

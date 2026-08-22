# Skill Radar

Watching the skill ecosystem without trusting it.

```bash
devforge skill radar                 # sweep and report: NEW, UPDATE, WARNING, DEPRECATE
devforge skill radar -o radar.md     # write the report instead of printing it
devforge skill outdated              # installed skills a sweep found a newer version of
devforge skill audit-all             # re-inspect everything already installed
devforge skill recommend             # what is worth a person's review, best first
```

Exit codes: `radar` and `audit-all` exit `1` when there is a WARNING, a DEPRECATE
or a blocking finding — those are things somebody has to look at. Finding
candidates is not an error.

## What the radar can and cannot see

**It does not crawl.** DevForge imports no HTTP client:
`tests/test_architecture.py` enforces it, `tests/test_radar.py` enforces it again
for this package, and the threat model depends on it. So the radar cannot search
GitHub, query an advisory database, or follow a link.

Discovery is therefore bounded by what an operator connects it to, and it grows
three ways:

| path | what it brings |
| --- | --- |
| `radar/radar.yaml` | organisations, repositories and topics somebody decided to watch |
| `radar/feeds/*.yaml` | candidate lists an operator exported and dropped in — the only path that carries genuinely new names |
| propagation | a fork, mirror or successor named by something already known becomes a watched source, with its origin recorded |

**Coverage is reported, always.** Every report lists the sources it consulted and
the ones it could not, with reasons — an empty advisory file reads as "nothing
recorded locally, which is not the same as none existing". A radar whose blind
spots are invisible reads as though it looked everywhere.

## Scoring

Three inputs, out of 113, normalised to 100.

**Quality (90).** The supply-chain scorer, unchanged: maintenance, activity,
documentation, tests, licence, portability, security posture, dependency risk,
capability coverage. It already excludes popularity, on evidence recorded in its
own docstring — the Phase 0 survey found the most-starred source shipping
auto-executing session hooks and the least-starred one shipping CODEOWNERS.

**Fit (20).** *Usefulness* against the capabilities this project declared it
wants, minus a *duplication* penalty for skills it already runs. Fit is computed
here rather than in the quality scorer because it is a property of the
relationship: a perfectly-made skill that duplicates one you already have is a
bad adoption, and no amount of scoring the skill alone will say so.

**Popularity (3).** Stars, capped hard. The brief permits stars to be considered
and forbids them dominating; a cap is the only way to guarantee the second half,
and the test that matters asserts that maximum stars cannot move a poor candidate
to INSTALL.

**A score without a local copy is a metadata score**, and says so. Documentation,
tests, portability, security posture and dependency risk cannot be read from a
name, so they stay at zero rather than being guessed upward. A candidate nobody
has fetched scores low, which is correct — nobody has looked at it. Fetching it
through `devforge skill install` is what produces a real score.

## Security gates; it does not add points

Seven checks, in the order the brief lists them: source verification, licence
verification, static inspection, dependency inspection, script inspection,
permission analysis, advisory check.

The result is a **gate, not a term**. A candidate with a blocking finding is a
WARNING whatever else is true about it, because "install this" and "this ships an
arbitrary shell installer" are not two considerations to trade off. Trading them
is how a scoring system ends up recommending the thing it was built to catch.

**A check that could not run is reported as unavailable, never as passed.**
Without a local copy, the four content checks say so by name. With no advisories
recorded, the advisory check says so too.

Advisories are local: `radar/advisories.yaml` holds what somebody read elsewhere
and wrote down. High and critical ones block; an advisory against an *installed*
skill is raised even when no feed mentions it, because that is the case that
matters most.

## Verdicts

| verdict | meaning |
| --- | --- |
| `INSTALL` | scores above the threshold with a clean inspection — **worth a person's review**, not "safe" |
| `REVIEW` | scores above the review threshold, with something a person should read first |
| `WATCH` | below threshold, or already covered by something installed |
| `WARN` | a blocking finding or a serious advisory |
| `DEPRECATE` | archived, deprecated upstream, or under a critical advisory |

Every verdict carries a one-sentence reason saying why this and not the next one
up, and a test asserts none is ever empty.

## Nothing here installs anything

`recommend` produces sentences for a person. Installation stays behind
`devforge skill install`, its approval gate, its inspection and its lockfile —
which is where a human already has to decide, and where the supply-chain
machinery already lives. A test asserts the radar package imports none of the
install functions.

## `audit-all`

`devforge skill audit` asks whether to install one skill. `audit-all` asks a
different question about what is already running: **is it still what you thought
it was?**

Two things change under a skill's feet without anyone touching it. Its content
can drift from the hash the lockfile recorded — somebody edited a file in place,
or an update landed unreviewed — and an advisory can be published against a
version that was fine when it was installed. Neither is visible from inside the
skill, so both are checked here. Content drift is reported as a finding about the
*process*, not about the code.

## Limits

**Every candidate is untrusted, including the ones that score well.** A score
reads the shape of a repository — does it have tests, a licence, recent commits,
a security policy. It is not an audit of what the skill's instructions will make
a model do, and that is the risk that actually matters for a skill.

**Feeds are as good as whoever wrote them.** A feed is operator-supplied data;
the radar records where each candidate came from and when, so a stale or partial
feed is visible as stale or partial rather than silently authoritative.

**"Nothing found" is not "nothing exists."** That sentence appears in the output
of every command here, because it is the mistake the whole design is arranged to
prevent.

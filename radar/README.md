# radar/

What the Skill Radar watches, and what it has been told.

| file | what it is |
| --- | --- |
| `radar.yaml` | sources to watch, capabilities this project wants, score thresholds |
| `advisories.yaml` | advisories an operator read elsewhere and recorded here |
| `feeds/*.yaml` | candidate lists an operator exported and dropped in |

## Why feeds exist

DevForge imports no HTTP client. `tests/test_architecture.py` enforces it and the
threat model depends on it, so the radar cannot search GitHub, query an advisory
database, or crawl anything.

A feed is how new names get in: export a search, paste a colleague's list, dump a
digest — anything shaped like `feeds/example.yaml`. The radar parses it, scores
what it contains, and records which feed each candidate came from and when the
feed was gathered. **An undated feed is reported as undated**, not as fresh.

## Coverage is stated, not assumed

Every report lists the sources it consulted *and* the ones it could not, with
reasons. A radar whose blind spots are invisible reads as though it looked
everywhere; this one tells you the shape of the hole.

## Nothing here installs anything

`devforge skill radar` and `devforge skill recommend` produce sentences for a
person. Installation stays behind `devforge skill install`, its approval gate and
its lockfile.

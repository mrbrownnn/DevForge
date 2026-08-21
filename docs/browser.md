# Browser intelligence and visual verification

A browser agent is the highest-risk component in DevForge. It fetches content chosen
by whoever controls the site, renders it, and hands the result to a model that holds
tool permissions. This page describes what it can do, what it refuses to do, and what
its verdicts do and do not prove.

Both halves are optional dependencies:

```bash
pip install "devforge[browser]" && playwright install chromium   # capture
pip install "devforge[visual]"                                   # pixel corroboration
```

Without the driver the browser tool reports `unavailable` and the visual verifier
reports `unavailable`. Neither fabricates a result, and neither reports `passed`.

## The capture layer

`devforge.browser.session.BrowserSession` opens one isolated context per session and
`devforge.browser.capture.capture_page` turns a rendered page into a `PageSnapshot`:
element geometry, computed styles, the asset inventory, the requests the page made,
a screenshot path, the palette and font families actually painted, and a bounded text
excerpt.

Collection is one pass of JavaScript in the page rather than a call per element,
because a per-element round trip turns a one-second capture into a one-minute one.
Only laid-out, visible elements are recorded, capped at 400 — a full DOM dump of a
real site is mostly wrappers, and comparing wrappers produces noise that reads like
findings.

### The browser tool

`browser` exposes ten actions: `fetch`, `text`, `html`, `title`, `screenshot`,
`snapshot`, `inspect`, `styles`, `assets`, `network`. Each takes a URL and an optional
viewport (`mobile`, `tablet`, `desktop`) and interaction list.

Interactions are a **closed vocabulary**: `click`, `type`, `scroll`, `wait`. There is
deliberately no `evaluate` step. Accepting a JavaScript string from a caller would —
one indirection later, via a page that talked the agent into it — hand arbitrary
execution to whoever wrote the page. The schema is validated at the tool boundary,
nested objects included, so an unknown step is refused rather than ignored.

## What the browser refuses

| Threat | What stops it |
| --- | --- |
| SSRF via the URL the agent chose | The tool checks the URL against the network policy before opening anything. Network access is off by default. |
| SSRF via a page's own subresources | A route handler applies the same policy to **every** request the page makes, not just the first. A public page cannot pull `http://169.254.169.254/` on our behalf. |
| `file://` and `data:` navigation | Scheme allowlist: `http`, `https`, `about`, `blob`. Everything else is refused before a context is touched. |
| Developer credential exposure | The context is created empty — no profile directory, no `storage_state`, no cookie jar. There is no code path that could pass one, which is stronger than a rule saying not to. |
| Persistence leakage between pages | A fresh context per session. Cookies, `localStorage` and cache die with it, so one capture cannot read what another left. |
| Downloads | `accept_downloads=False`, and any download event is cancelled. A browser that writes to disk is a remote-driven file-write primitive. |
| Dialogs stalling the run | Dismissed automatically; waits are capped at five seconds and interaction lists at twenty steps. |
| Prompt injection in page content | Page text and element text come back through `devforge.tools.untrusted.wrap`: fenced, labelled, and scanned. Nothing read from a page is treated as instruction. |

Loopback is treated as private and refused, like any other internal address. Local
development is the one legitimate exception, so it is a narrow opt-in
(`network.allow_loopback: true`) rather than a reason to disable the SSRF defence.

### What this is not

Not a sandbox. Chromium runs as the invoking user, with Chromium's own sandbox — which
is real, but is Chromium's, not DevForge's. A browser exploit is out of scope, and the
honest mitigation is the same as everywhere else in this project: do not point it at
input you would not open yourself.

## Visual verification

`devforge.visual.compare` answers "does the reproduction look like the original?" with
structure first and pixels second.

A pixel-diff percentage tells you *that* two pages differ. It does not tell you the
heading is 24px instead of 32px, which is the thing someone can act on. Worse, it
misleads in both directions: two pages can differ by 30% of pixels and be correct (a
different photo) or by 2% and be wrong (an illegible heading). So the verdict comes
from matched elements and their computed properties, and the pixel ratio is recorded
alongside as corroboration.

Elements are matched by selector, then by tag plus text, then by tag order — a clone
reproduces the design, not the class names, so selector-only matching would report
every element as missing.

Findings are categorised as `layout`, `dimensions`, `typography`, `spacing`, `colors`,
`images`, `responsive` or `pixels`, and graded `info` / `minor` / `major`. Tolerances
exist because two renders of the *same* page differ slightly — fonts hint differently,
sub-pixel layout rounds differently — and a report that cries wolf stops being read.

The verdict is `PASS`, `FAIL`, or `UNVERIFIED`. There is no "probably fine". Any major
finding fails. `UNVERIFIED` appears whenever the evidence was not there, and for a
required verifier that blocks the run exactly like a failure.

### Configuring the verifier

```yaml
verifiers:
  - id: visual
    kind: visual
    required: true
    params:
      reference: https://example.com     # the site being reproduced
      serve: site                        # DevForge serves this itself
      viewports: [mobile, tablet, desktop]
      threshold: 0.9
      report: site/VISUAL-REPORT.md
```

`serve` is what lets the clone loop close with no external dependency: DevForge serves
that workspace directory on an ephemeral **loopback** port for the length of the
comparison and uses it as the candidate. It is bound to `127.0.0.1`, serves one
directory read-only, and is shut down when the comparison ends — a verification
fixture, not a web server. Use `candidate: <url>` instead when a build is already
running somewhere.

The reference keeps the project's full network policy; only the served side gets the
loopback carve-out, so a redirect from the reference site cannot reach this machine's
own services.

## The clone workflow

`devforge run --workflow clone` runs: reconnaissance → design analysis → **human
approval** → implementation → visual refinement (the repair loop) → an independent
verification checkpoint → final approval.

The refinement step is the loop. When the visual verifier fails, its diff becomes the
repair briefing for the next attempt, up to `max_attempts`. The step passes only when
the comparison clears the threshold.

Before running it, copy the built-in to `<project>/workflows/clone.yaml` and set
`params.reference` plus `network.allow_hosts`. The built-in ships without a reference
URL on purpose: the target is task-specific, and shipping a default would mean
comparing against a guess.

## What a passing report does not say

It does not say the reproduction is pixel perfect. Every report ends with that
sentence and names what it compared, what it found, and what it could not check.
Anything absent from the reference snapshot was not verified at all.

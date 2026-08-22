"""Skill Radar: watching the skill ecosystem without trusting it.

The radar answers one question repeatedly - *is there anything out there worth
adopting, and has anything we already adopted gone bad?* - and produces a report
in four sections: NEW, UPDATE, WARNING, DEPRECATE.

It is built on the supply-chain layer rather than beside it. Fetching, static
inspection, risk classification and quality scoring already exist and are already
tested; the radar adds discovery, *fit*, verdicts and the report. A second
implementation of any of those would be a second thing to keep correct.

Two things this package will not do
-----------------------------------

**It does not crawl the internet.** DevForge imports no HTTP client - an
architecture test enforces it, and the threat model depends on it. Discovery is
bounded by what an operator connects the radar to: configured organisations and
repositories, feeds they export and drop in, and what the local registry and
catalogue already know. That boundary is stated in every report, because a radar
whose coverage is assumed to be total is worse than one whose coverage is known
to be partial.

**It never installs anything.** A recommendation is a sentence for a person to
act on. Installation stays behind ``devforge skill install``, its approval gate
and its lockfile - which is where a human already has to decide.
"""

"""Continuous engineering: finding work that nobody has filed yet.

Everything else in DevForge waits to be asked. This package looks at a repository
and proposes what is worth doing - security issues, stale dependencies, flaky
tests, dead and duplicated code, architectural smells, debt markers, untested
surface, performance patterns and documentation that has drifted from the code it
describes.

Two constraints shape all of it.

**Nothing here modifies code.** Detection produces findings; findings produce
proposals; a proposal becomes work only after a human approves it, and the work
itself runs through the ordinary workflow with its ordinary gates. A tool that
tidies your repository while you are not looking is not a colleague.

**Nothing here files noise.** A low-confidence finding costs more than it saves:
it trains people to ignore the list, and a list that gets ignored may as well not
exist. Detectors carry a calibrated confidence, low-confidence findings are
withheld by default rather than filed with a caveat, and a detector that cannot
run says so instead of returning nothing.
"""

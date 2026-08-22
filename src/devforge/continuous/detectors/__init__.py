"""The ten detectors.

Each one answers a single question about a repository, reports what it examined,
and says so when it cannot run. A detector that returns an empty list because it
crashed is indistinguishable from a clean repository, which is the failure mode
this interface exists to prevent: ``DetectorStatus.UNAVAILABLE`` carries a reason
and never counts as "nothing found".

Confidence is a stated property of each rule, not a number a model produced. It
answers "how often is this rule right when it fires", and it is what keeps the
backlog usable - anything below the threshold is withheld rather than filed with
a caveat nobody reads.
"""

from __future__ import annotations

from devforge.continuous.detectors.base import (
    DETECTORS,
    Detector,
    SourceFile,
    read_sources,
)

__all__ = ["DETECTORS", "Detector", "SourceFile", "read_sources"]

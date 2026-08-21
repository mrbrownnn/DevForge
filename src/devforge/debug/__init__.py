"""Autonomous debugging: reproduction, evidence, patch review and repair reports.

The pipeline is deliberately split into modules that do not depend on each other:
:mod:`~devforge.debug.reproduce` proves the defect exists,
:mod:`~devforge.debug.evidence` records what was observed,
:mod:`~devforge.debug.patch_guard` reads the resulting patch for the ways a repair
can cheat, and :mod:`~devforge.debug.benchmark` scores the whole thing against
seeded defects with known fixes.

Nothing here imports a runtime or an agent. Debugging is a set of measurements;
who or what proposes the patch is somebody else's problem.
"""

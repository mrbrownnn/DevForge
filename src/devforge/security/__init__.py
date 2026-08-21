"""The Security Center: threat model, posture audit, workspace scan, inventory.

Split by the question each part answers, because mixing them is how security
tooling starts overstating what it knows:

* :mod:`~devforge.security.catalog` - the threats and the defence-in-depth layers
  as data, so a claim about a control can be checked against the tree.
* :mod:`~devforge.security.audit` - is this installation configured the way the
  threat model says it is?
* :mod:`~devforge.security.scan` - is there anything dangerous in this workspace?
* :mod:`~devforge.security.sbom` - what is installed, and where did it come from?
* :mod:`~devforge.security.report` - all of the above, plus the residual risk that
  survives every passing check.

Nothing here computes a score or emits a verdict. See the note in
:mod:`~devforge.security.models` for why.
"""

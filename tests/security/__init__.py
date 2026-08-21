"""Adversarial tests and Security Center tests.

Kept in their own package because they are read differently from the rest of the
suite. A normal test asks "does this work?"; these ask "does this refuse?", and
every one of them is written from the attacker's side of the boundary.

The rule this directory exists to enforce: **every security regression becomes a
permanent test here.** A control that was once broken and then fixed will be
broken again by a future refactor unless something fails loudly when it is.
"""

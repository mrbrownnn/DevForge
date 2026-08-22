"""Git-native engineering: worktrees, guarded operations, commits, PR artifacts.

DevForge writes to real repositories that people are working in. That makes two
rules structural rather than aspirational:

**The user's checked-out branch is not ours.** Autonomous work happens in an
isolated worktree on its own branch. Nothing here checks out, resets or rebases
the branch you are standing on.

**History is not editable without a person.** Force push, branch deletion and
every form of history rewriting are refused unless a human approval exists for
that specific operation. They are the operations whose damage cannot be undone
from inside the tool that caused it.
"""

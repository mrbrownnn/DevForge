"""The backlog: approval, execution and verification.

This is where the pipeline stops being analysis and starts being work, so it is
where the constraint lives:

**Nothing executes without an approval that a human recorded.** ``execute``
refuses a proposal that is not approved, and what it does when approved is
*prepare* - an isolated worktree, and the proposal written into it as an issue.
It does not edit code. The work itself runs through the ordinary workflow, with
the ordinary verifiers and the ordinary gates.

**Verification re-runs the detector.** A proposal is verified when the findings
that motivated it stop firing - not when a workflow reports success, and not when
an agent says it is done. That is the only check that cannot be satisfied by
saying so.
"""

from __future__ import annotations

from datetime import date, datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from devforge.continuous.engine import detect
from devforge.continuous.models import (
    Category,
    Proposal,
    ProposalState,
    Suppression,
)
from devforge.core.errors import ConfigError
from devforge.core.models import utcnow

BACKLOG_DIRNAME = "continuous"
BACKLOG_FILENAME = "backlog.json"
#: Where accepted findings are recorded, next to the security baseline it mirrors.
ACCEPTED_FILENAME = "accepted.yaml"


class Backlog(BaseModel):
    """Every proposal this project has seen, and what happened to it."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    updated_at: datetime = Field(default_factory=utcnow)
    proposals: list[Proposal] = Field(default_factory=list)

    def get(self, proposal_id: str) -> Proposal | None:
        return next((p for p in self.proposals if p.proposal_id == proposal_id), None)

    def require(self, proposal_id: str) -> Proposal:
        proposal = self.get(proposal_id)
        if proposal is None:
            raise ConfigError(f"no proposal '{proposal_id}' in the backlog")
        return proposal

    @property
    def open(self) -> list[Proposal]:
        return sorted(
            [p for p in self.proposals if p.state.open],
            key=lambda proposal: -proposal.priority,
        )

    def merge(self, proposals: list[Proposal]) -> tuple[list[Proposal], list[Proposal]]:
        """Add proposals that are new, keeping the state of ones already here.

        Returns ``(added, already_known)``. Re-running detection must not reset a
        rejected proposal to proposed - a decision someone made stays made until
        they change it, or the backlog would ask the same question every day.
        """
        known = {_fingerprint(proposal): proposal for proposal in self.proposals}
        added: list[Proposal] = []
        existing: list[Proposal] = []
        for proposal in proposals:
            match = known.get(_fingerprint(proposal))
            if match is None:
                self.proposals.append(proposal)
                added.append(proposal)
            else:
                existing.append(match)
        self.updated_at = utcnow()
        return added, existing


def _fingerprint(proposal: Proposal) -> str:
    """Identity across runs: the findings it is about, not the id it was given."""
    return "|".join(sorted(finding.key() for finding in proposal.findings))


# --------------------------------------------------------------------------- storage


def backlog_path(root: Path) -> Path:
    return Path(root) / ".devforge" / BACKLOG_DIRNAME / BACKLOG_FILENAME


def load_backlog(root: Path) -> Backlog:
    path = backlog_path(root)
    if not path.is_file():
        return Backlog()
    try:
        return Backlog.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        # Fails closed: an unreadable backlog must not silently become an empty
        # one, which would re-propose everything and lose every past decision.
        raise ConfigError(f"could not read the backlog at {path}: {exc}") from exc


def save_backlog(backlog: Backlog, root: Path) -> Path:
    path = backlog_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(backlog.model_dump_json(indent=1), encoding="utf-8")
    return path


def accepted_path(root: Path) -> Path:
    return Path(root) / ".devforge" / BACKLOG_DIRNAME / ACCEPTED_FILENAME


def load_accepted(root: Path) -> list[Suppression]:
    """Findings a human has looked at and decided not to act on.

    Same shape as the security baseline, and for the same reason: an acceptance
    costs a written reason and an expiry date, so a decision nobody has
    re-confirmed becomes visible again instead of becoming permanent.
    """
    path = accepted_path(root)
    if not path.is_file():
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"could not read {path}: {exc}") from exc
    entries = raw.get("accepted", []) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ConfigError(f"{path}: expected a list under 'accepted'")
    try:
        return [Suppression.model_validate(entry) for entry in entries]
    except ValidationError as exc:
        raise ConfigError(f"{path}: invalid acceptance: {exc}") from exc


# --------------------------------------------------------------------------- stages


def approve(
    backlog: Backlog, proposal_id: str, *, by: str = "", reason: str = ""
) -> Proposal:
    proposal = backlog.require(proposal_id)
    if proposal.state is ProposalState.VERIFIED:
        raise ConfigError(f"proposal '{proposal_id}' is already verified")
    proposal.state = ProposalState.APPROVED
    proposal.decided_by = by
    proposal.decided_at = utcnow()
    proposal.reason = reason
    backlog.updated_at = utcnow()
    return proposal


def reject(backlog: Backlog, proposal_id: str, *, by: str = "", reason: str = "") -> Proposal:
    proposal = backlog.require(proposal_id)
    proposal.state = ProposalState.REJECTED
    proposal.decided_by = by
    proposal.decided_at = utcnow()
    proposal.reason = reason
    backlog.updated_at = utcnow()
    return proposal


class Preparation(BaseModel):
    """What ``execute`` produced: a place to work and the brief to work from."""

    model_config = ConfigDict(extra="forbid")

    proposal_id: str
    worktree: str
    branch: str
    issue_path: str
    workflow: str

    def next_command(self) -> str:
        return f"devforge run --workflow {self.workflow} --task @ISSUE.md"


def execute(backlog: Backlog, proposal_id: str, root: Path) -> Preparation:
    """Prepare an approved proposal for work. Changes no source file.

    The isolation is the whole point: the work happens on its own branch in its
    own worktree, so an accepted proposal that turns out to be wrong costs a
    deleted directory rather than a revert on the branch someone is using.
    """
    from devforge.vcs.worktree import create_worktree, repository_root

    proposal = backlog.require(proposal_id)
    if proposal.state is not ProposalState.APPROVED:
        raise ConfigError(
            f"proposal '{proposal_id}' is {proposal.state.value}, not approved. "
            "Continuous engineering does not act on findings a human has not agreed to."
        )

    repository = repository_root(Path(root))
    worktree = create_worktree(
        repository,
        branch=proposal.branch or f"chore/{proposal.proposal_id}",
        issue_id=proposal.proposal_id,
    )
    issue = Path(worktree.path) / "ISSUE.md"
    issue.write_text(proposal.issue_body(), encoding="utf-8")

    proposal.state = ProposalState.EXECUTING
    backlog.updated_at = utcnow()
    return Preparation(
        proposal_id=proposal.proposal_id,
        worktree=worktree.path,
        branch=worktree.branch,
        issue_path=str(issue),
        workflow=proposal.workflow,
    )


class Verification(BaseModel):
    """Whether the findings that motivated a proposal have stopped firing."""

    model_config = ConfigDict(extra="forbid")

    proposal_id: str
    resolved: list[str] = Field(default_factory=list)
    remaining: list[str] = Field(default_factory=list)
    #: Categories whose detector could not run, so their findings are unproven
    #: either way. Never counted as resolved.
    unverifiable: list[str] = Field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.remaining and not self.unverifiable


def verify(
    backlog: Backlog,
    proposal_id: str,
    root: Path,
    *,
    today: date | None = None,
) -> Verification:
    """Re-run the detectors that produced this proposal, in the given tree.

    This is the check an agent cannot satisfy by claiming success. If the finding
    still fires, the work is not done, whatever the workflow reported.
    """
    proposal = backlog.require(proposal_id)
    categories: list[Category] = sorted(
        {finding.category for finding in proposal.findings}, key=lambda c: c.value
    )
    report = detect(Path(root), categories=categories, today=today)

    still_firing = {finding.key() for finding in report.findings}
    unavailable = {report_.category for report_ in report.unavailable}

    result = Verification(proposal_id=proposal.proposal_id)
    for finding in proposal.findings:
        if finding.category in unavailable:
            result.unverifiable.append(finding.key())
        elif finding.key() in still_firing:
            result.remaining.append(finding.key())
        else:
            result.resolved.append(finding.key())

    proposal.state = ProposalState.VERIFIED if result.complete else ProposalState.FAILED
    backlog.updated_at = utcnow()
    return result


def summarise(backlog: Backlog) -> dict[str, int]:
    counts: dict[str, int] = {}
    for proposal in backlog.proposals:
        counts[proposal.state.value] = counts.get(proposal.state.value, 0) + 1
    return counts


__all__ = [
    "Backlog",
    "Preparation",
    "Verification",
    "accepted_path",
    "approve",
    "backlog_path",
    "execute",
    "load_accepted",
    "load_backlog",
    "reject",
    "save_backlog",
    "summarise",
    "verify",
]

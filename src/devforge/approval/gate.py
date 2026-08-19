"""Human approval gates.

A gate does not block a thread. Reaching one records a pending
:class:`~devforge.core.models.Approval` on the task, marks the run
``awaiting_approval`` and returns control, so the process can exit and the
decision can arrive minutes or days later through ``devforge approve``. That is
what makes approvals survive a closed terminal.

An optional ``prompter`` supports ``devforge run --interactive``, where the same
decision is taken inline. The persisted record is the source of truth either way.
"""

from __future__ import annotations

from collections.abc import Callable

from devforge.core.models import Approval, ApprovalStatus, Task, utcnow
from devforge.policy.engine import PolicyEngine

Prompter = Callable[[Approval], bool]

AUTO_APPROVER = "policy:auto_approve"
NON_BLOCKING_APPROVER = "policy:non_blocking"
INTERACTIVE_APPROVER = "interactive"


class ApprovalGate:
    """Requests and resolves approvals against a task."""

    def __init__(self, policy: PolicyEngine, *, prompter: Prompter | None = None) -> None:
        self.policy = policy
        self.prompter = prompter

    def existing(self, task: Task, gate: str, step_id: str) -> Approval | None:
        for approval in task.approvals:
            if approval.gate == gate and approval.step_id == step_id:
                return approval
        return None

    def request(
        self,
        task: Task,
        *,
        gate: str,
        step_id: str,
        prompt: str = "",
        context: dict | None = None,
    ) -> Approval:
        """Return the approval for this gate, deciding it now only if policy allows.

        The returned approval is ``PENDING`` when a human still has to act.
        """
        approval = self.existing(task, gate, step_id)
        if approval is not None and approval.status is not ApprovalStatus.PENDING:
            return approval

        if approval is None:
            approval = Approval(
                gate=gate,
                step_id=step_id,
                prompt=prompt or self.policy.approvals.gate(gate).description,
                context=context or {},
            )
            task.approvals.append(approval)
            task.touch()

        gate_policy = self.policy.approvals.gate(gate)
        if gate_policy.auto_approve:
            return self._decide(task, approval, True, AUTO_APPROVER, "auto-approved by policy")
        if not gate_policy.blocking:
            return self._decide(
                task, approval, True, NON_BLOCKING_APPROVER, "gate is declared non-blocking"
            )
        if self.prompter is not None:
            granted = self.prompter(approval)
            return self._decide(
                task,
                approval,
                granted,
                INTERACTIVE_APPROVER,
                "approved interactively" if granted else "rejected interactively",
            )
        return approval

    def resolve(
        self,
        task: Task,
        *,
        gate: str,
        step_id: str | None = None,
        approved: bool,
        by: str = "human",
        reason: str = "",
    ) -> Approval:
        """Record a human decision. Raises ``KeyError`` if the gate was never requested."""
        approval = None
        for candidate in task.approvals:
            if candidate.gate != gate:
                continue
            if step_id is not None and candidate.step_id != step_id:
                continue
            if candidate.status is ApprovalStatus.PENDING:
                approval = candidate
                break
            approval = approval or candidate
        if approval is None:
            raise KeyError(gate)
        return self._decide(task, approval, approved, by, reason)

    def pending(self, task: Task) -> list[Approval]:
        return [a for a in task.approvals if a.status is ApprovalStatus.PENDING]

    @staticmethod
    def _decide(task: Task, approval: Approval, approved: bool, by: str, reason: str) -> Approval:
        approval.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        approval.decided_at = utcnow()
        approval.decided_by = by
        approval.reason = reason
        task.touch()
        return approval

from __future__ import annotations

from pathlib import Path

import pytest

from devforge.approval.gate import ApprovalGate
from devforge.core.models import Approval, ApprovalStatus, Task
from devforge.policy.engine import PolicyEngine
from devforge.policy.models import ApprovalPolicy, GatePolicy, PermissionPolicy


@pytest.fixture()
def task() -> Task:
    return Task(project_id="p", description="d", workflow="feature")


def engine_with(gates: dict[str, GatePolicy], tmp_path: Path) -> PolicyEngine:
    return PolicyEngine(
        PermissionPolicy(), ApprovalPolicy(gates=gates), workspace=tmp_path
    )


def test_gate_records_pending_approval(tmp_path: Path, task: Task) -> None:
    gate = ApprovalGate(engine_with({"architecture": GatePolicy(blocking=True)}, tmp_path))

    approval = gate.request(task, gate="architecture", step_id="approve-architecture")

    assert approval.status is ApprovalStatus.PENDING
    assert task.approvals == [approval]
    assert gate.pending(task) == [approval]


def test_requesting_twice_does_not_duplicate(tmp_path: Path, task: Task) -> None:
    gate = ApprovalGate(engine_with({"architecture": GatePolicy()}, tmp_path))

    gate.request(task, gate="architecture", step_id="s")
    gate.request(task, gate="architecture", step_id="s")

    assert len(task.approvals) == 1


def test_resolve_marks_approved(tmp_path: Path, task: Task) -> None:
    gate = ApprovalGate(engine_with({"architecture": GatePolicy()}, tmp_path))
    gate.request(task, gate="architecture", step_id="s")

    approval = gate.resolve(task, gate="architecture", approved=True, by="alice", reason="looks good")

    assert approval.status is ApprovalStatus.APPROVED
    assert approval.decided_by == "alice" and approval.decided_at is not None
    assert gate.pending(task) == []


def test_resolve_marks_rejected(tmp_path: Path, task: Task) -> None:
    gate = ApprovalGate(engine_with({"architecture": GatePolicy()}, tmp_path))
    gate.request(task, gate="architecture", step_id="s")

    approval = gate.resolve(task, gate="architecture", approved=False, reason="wrong layer")

    assert approval.status is ApprovalStatus.REJECTED
    assert approval.reason == "wrong layer"


def test_decided_gate_is_not_reopened(tmp_path: Path, task: Task) -> None:
    gate = ApprovalGate(engine_with({"architecture": GatePolicy()}, tmp_path))
    gate.request(task, gate="architecture", step_id="s")
    gate.resolve(task, gate="architecture", approved=True)

    again = gate.request(task, gate="architecture", step_id="s")

    assert again.status is ApprovalStatus.APPROVED
    assert len(task.approvals) == 1


def test_resolving_unknown_gate_raises(tmp_path: Path, task: Task) -> None:
    gate = ApprovalGate(engine_with({}, tmp_path))

    with pytest.raises(KeyError):
        gate.resolve(task, gate="nope", approved=True)


def test_auto_approve_is_opt_in(tmp_path: Path, task: Task) -> None:
    gate = ApprovalGate(engine_with({"ci": GatePolicy(auto_approve=True)}, tmp_path))

    approval = gate.request(task, gate="ci", step_id="s")

    assert approval.status is ApprovalStatus.APPROVED
    assert approval.decided_by == "policy:auto_approve"


def test_non_blocking_gate_records_but_does_not_wait(tmp_path: Path, task: Task) -> None:
    gate = ApprovalGate(engine_with({"advisory": GatePolicy(blocking=False)}, tmp_path))

    approval = gate.request(task, gate="advisory", step_id="s")

    assert approval.status is ApprovalStatus.APPROVED
    assert approval.decided_by == "policy:non_blocking"


def test_undeclared_gate_blocks(tmp_path: Path, task: Task) -> None:
    gate = ApprovalGate(engine_with({}, tmp_path))

    approval = gate.request(task, gate="mystery", step_id="s")

    assert approval.status is ApprovalStatus.PENDING, "unknown gates must fail closed"


def test_interactive_prompter_decides_inline(tmp_path: Path, task: Task) -> None:
    seen: list[Approval] = []

    def prompter(approval: Approval) -> bool:
        seen.append(approval)
        return True

    gate = ApprovalGate(engine_with({"architecture": GatePolicy()}, tmp_path), prompter=prompter)
    approval = gate.request(task, gate="architecture", step_id="s", prompt="approve design?")

    assert approval.status is ApprovalStatus.APPROVED
    assert approval.decided_by == "interactive"
    assert seen[0].prompt == "approve design?"


def test_interactive_rejection_is_recorded(tmp_path: Path, task: Task) -> None:
    gate = ApprovalGate(engine_with({"architecture": GatePolicy()}, tmp_path), prompter=lambda _: False)

    approval = gate.request(task, gate="architecture", step_id="s")

    assert approval.status is ApprovalStatus.REJECTED


def test_approvals_survive_persistence(project, task: Task) -> None:
    gate = ApprovalGate(PolicyEngine.load(None, workspace=project.root))
    gate.request(task, gate="architecture", step_id="approve-architecture", prompt="ok?")
    project.save_task(task)

    reloaded = project.load_task(task.task_id)
    assert reloaded.approvals[0].status is ApprovalStatus.PENDING

    gate.resolve(reloaded, gate="architecture", approved=True, by="bob")
    project.save_task(reloaded)

    final = project.load_task(task.task_id)
    assert final.approvals[0].status is ApprovalStatus.APPROVED
    assert final.approvals[0].decided_by == "bob"

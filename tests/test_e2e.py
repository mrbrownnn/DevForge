"""End-to-end test.

Exercises the whole harness through the CLI with no paid API call anywhere:

    devforge init
      -> devforge run   (mock runtime, verification fails, agent repairs, passes)
      -> pauses at a human approval gate
      -> devforge approve
      -> devforge run --resume
      -> completed, with state, verification records and event log on disk

The project under test brings its own workflow and its own permission policy, which
is also how a real project customises DevForge.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from devforge.cli.main import app
from devforge.core.models import StepStatus, TaskStatus, VerificationStatus
from devforge.core.state.store import ProjectStore

runner = CliRunner()

# Fails the first time it runs, passes afterwards - a deterministic stand-in for
# "the agent's first attempt did not actually work".
FLAKY_CHECK = """
import pathlib, sys
marker = pathlib.Path("attempts.txt")
count = (int(marker.read_text()) if marker.exists() else 0) + 1
marker.write_text(str(count))
if count < 2:
    print("FAIL: expected 401, got 200")
    sys.exit(1)
print("OK: 3 passed")
"""

WORKFLOW = """
name: e2e
description: Minimal feature workflow used by the end-to-end test.
verifiers:
  - id: tests
    kind: tests
    argv: [{python}, check.py]
    timeout_s: 60
    required: true
steps:
  - id: planning
    agent: architect
    description: Plan the change.
  - id: approve-architecture
    kind: approval
    gate: architecture
  - id: implementation
    agent: coder
    tools: [filesystem]
    verify: [tests]
    max_attempts: 3
  - id: review
    agent: reviewer
    description: Final review.
"""

# The built-in policy is deny-by-default and would refuse the absolute interpreter
# path used above; a project overriding policy is a supported, documented path.
POLICY = """
shell:
  default: deny
  allow: ["*"]
filesystem:
  workspace_only: true
  read: ["**"]
  write: ["**"]
  deny: ["**/.env", "**/secrets/**"]
  delete: require_approval
"""


def invoke(*args: str):
    return runner.invoke(app, list(args), env={"COLUMNS": "200"})


@pytest.fixture()
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "check.py").write_text(FLAKY_CHECK, encoding="utf-8")

    workflows = tmp_path / "workflows"
    workflows.mkdir()
    (workflows / "e2e.yaml").write_text(
        WORKFLOW.format(python=json.dumps(sys.executable)), encoding="utf-8"
    )

    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "permissions.yaml").write_text(POLICY, encoding="utf-8")
    return tmp_path


def test_full_run_through_the_cli(project: Path) -> None:
    assert invoke("init", "--name", "e2e").exit_code == 0
    store = ProjectStore.discover(project)

    # -- doctor sees the project and reports every adapter honestly
    doctor = json.loads(invoke("doctor", "--json").stdout)
    assert doctor["ok"] is True
    assert doctor["workflows"]["e2e"].startswith("ok")
    assert isinstance(doctor["tools"]["browser"]["available"], bool)

    # -- run: planning succeeds, then the run pauses at the approval gate
    first = invoke("run", "--workflow", "e2e", "--task", "Add JWT auth", "--runtime", "mock")
    assert first.exit_code == 2
    assert "awaiting approval" in first.stdout

    task_id = json.loads(invoke("status", "--json").stdout)["task_id"]
    paused = store.load_task(task_id)
    assert paused.status is TaskStatus.AWAITING_APPROVAL
    assert paused.step("planning").status is StepStatus.PASSED
    assert paused.step("implementation") is None, "work must not proceed past a pending gate"

    # -- a human approves out of band, exactly as a different terminal would
    assert invoke("approve", "--gate", "architecture", "--by", "thanh").exit_code == 0

    # -- resume: implementation fails verification once, repairs, then passes
    second = invoke("run", "--resume", task_id)
    assert second.exit_code == 0, second.stdout
    assert "run completed" in second.stdout

    # -- persisted state tells the whole story
    final = store.load_task(task_id)
    assert final.status is TaskStatus.COMPLETED
    assert [s.status for s in final.steps] == [StepStatus.PASSED] * 4
    assert final.approvals[0].decided_by == "thanh"

    implementation = final.step("implementation")
    assert implementation.attempt_count == 2
    assert implementation.attempts[0].status is StepStatus.FAILED
    assert implementation.attempts[1].status is StepStatus.PASSED

    statuses = [r.status for r in final.verification_results]
    assert statuses == [VerificationStatus.FAILED, VerificationStatus.PASSED]
    assert "expected 401" in final.verification_results[0].output_excerpt
    assert final.verification_results[0].exit_code == 1
    assert (project / "attempts.txt").read_text() == "2"

    # -- the run left a structured event log
    events = [
        json.loads(line)
        for line in store.events_path(task_id).read_text(encoding="utf-8").splitlines()
    ]
    names = [event["event"] for event in events]
    assert names.count("run.start") == 2, "resuming is a second run over the same task"
    assert "run.finish" in names
    assert "approval.pending" in names and "approval.granted" in names
    assert "verification.finish" in names

    repair = next(
        event
        for event in events
        if event["event"] == "agent.invoke" and event.get("mode") == "repair"
    )
    assert repair["step"] == "implementation" and repair["attempt"] == 2

    # -- review surfaces what the agents produced
    review = json.loads(invoke("review", "--json").stdout)
    step_ids = [step["step_id"] for step in review]
    assert step_ids == ["planning", "approve-architecture", "implementation", "review"]

    # -- no paid runtime was involved
    assert all(
        attempt["agent_result"]["runtime"] == "mock"
        for step in review
        for attempt in step["attempts"]
        if attempt["agent_result"]
    )

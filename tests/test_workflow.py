from __future__ import annotations

from pathlib import Path

import pytest

from devforge.core.errors import WorkflowError
from devforge.core.workflow.loader import WorkflowLoader, load_workflow_file
from devforge.core.workflow.spec import (
    OnFailure,
    StepKind,
    VerifierSpec,
    WorkflowSpec,
    WorkflowStep,
)

BUILTIN_WORKFLOWS = {"feature", "bugfix", "refactor", "clone", "demo", "multi-agent-feature"}


def write_workflow(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_all_builtin_workflows_parse() -> None:
    loader = WorkflowLoader.for_project(None)
    assert set(loader.available()) >= BUILTIN_WORKFLOWS

    for spec in loader.load_all():
        assert spec.steps
        assert not spec.missing_verifiers(set()), f"{spec.name} references undefined verifiers"


def test_feature_workflow_shape() -> None:
    spec = WorkflowLoader.for_project(None).load("feature")
    ids = [step.id for step in spec.steps]

    assert ids[0] == "requirements"
    assert "approve-architecture" in ids
    approval = spec.step("approve-architecture")
    assert approval.kind is StepKind.APPROVAL and approval.gate == "architecture"

    implementation = spec.step("implementation")
    assert implementation.kind is StepKind.AGENT
    assert implementation.agent == "coder"
    assert implementation.max_attempts == 3
    assert implementation.repairable


def test_clone_workflow_verifies_its_own_output() -> None:
    """Phase 6 made this real; what stays fixed is that it cannot pass unverified."""
    spec = WorkflowLoader.for_project(None).load("clone")

    assert spec.step("recon").tools == ["browser"]
    visual = next(v for v in spec.verifiers if v.id == "visual")
    assert visual.kind == "visual" and visual.required
    assert visual.params.get("reference") is None, (
        "the reference URL is task-specific; shipping one would compare against a guess"
    )


def test_agent_step_requires_agent() -> None:
    with pytest.raises(ValueError, match="agent steps require"):
        WorkflowStep(id="x")


def test_approval_step_requires_gate() -> None:
    with pytest.raises(ValueError, match="approval steps require"):
        WorkflowStep(id="x", kind=StepKind.APPROVAL)


def test_verify_step_requires_verifiers() -> None:
    with pytest.raises(ValueError, match="verify steps require"):
        WorkflowStep(id="x", kind=StepKind.VERIFY)


def test_step_defaults() -> None:
    step = WorkflowStep(id="unit-tests", agent="tester")

    assert step.name == "Unit Tests"
    assert step.on_failure is OnFailure.FAIL
    assert step.max_attempts == 3
    assert not step.repairable, "a step without verifiers cannot be repaired"


def test_command_verifier_requires_argv() -> None:
    with pytest.raises(ValueError, match="require 'argv'"):
        VerifierSpec(id="tests")
    assert VerifierSpec(id="visual", kind="visual").argv == []


def test_duplicate_step_ids_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate step id"):
        WorkflowSpec(
            name="w",
            steps=[WorkflowStep(id="a", agent="coder"), WorkflowStep(id="a", agent="tester")],
        )


def test_missing_verifiers_reported() -> None:
    spec = WorkflowSpec(
        name="w",
        steps=[WorkflowStep(id="a", agent="coder", verify=["tests", "lint"])],
        verifiers=[VerifierSpec(id="lint", argv=["ruff", "check"])],
    )

    assert spec.missing_verifiers(set()) == {"tests"}
    assert spec.missing_verifiers({"tests"}) == set()


def test_loader_reports_bad_yaml(tmp_path: Path) -> None:
    path = write_workflow(tmp_path / "broken.yaml", "steps: [\n")
    with pytest.raises(WorkflowError, match="invalid YAML"):
        load_workflow_file(path)


def test_loader_reports_validation_errors_with_location(tmp_path: Path) -> None:
    path = write_workflow(tmp_path / "bad.yaml", "steps:\n  - id: a\n    kind: nonsense\n")
    with pytest.raises(WorkflowError, match="steps.0.kind"):
        load_workflow_file(path)


def test_loader_requires_mapping(tmp_path: Path) -> None:
    path = write_workflow(tmp_path / "list.yaml", "- a\n- b\n")
    with pytest.raises(WorkflowError, match="must be a YAML mapping"):
        load_workflow_file(path)


def test_unknown_workflow_lists_available() -> None:
    loader = WorkflowLoader.for_project(None)
    with pytest.raises(
        WorkflowError,
        match=(
            "Available: bugfix, clone, demo, falsify, feature, git-feature, "
            "multi-agent-feature, refactor"
        ),
    ):
        loader.load("nope")


def test_project_workflow_overrides_builtin(tmp_path: Path) -> None:
    directory = tmp_path / "workflows"
    directory.mkdir()
    write_workflow(
        directory / "feature.yaml",
        "description: local override\nsteps:\n  - id: only\n    agent: coder\n",
    )

    spec = WorkflowLoader.for_project(tmp_path).load("feature")
    assert spec.description == "local override"
    assert [s.id for s in spec.steps] == ["only"]
    assert "clone" in WorkflowLoader.for_project(tmp_path).available()


def test_index_of_and_step_lookup() -> None:
    spec = WorkflowLoader.for_project(None).load("bugfix")
    assert spec.index_of("repair") > spec.index_of("reproduce")
    assert spec.step("missing") is None
    with pytest.raises(KeyError):
        spec.index_of("missing")


def test_bugfix_workflow_cannot_pass_by_weakening_the_tests() -> None:
    """The repair loop is only trustworthy if its exits are all guarded.

    A green suite is the easiest thing in the world to produce dishonestly, so the
    patch review and the written report are required verifiers, not optional
    niceties, and the repair step runs them on every attempt.
    """
    spec = WorkflowLoader.for_project(None).load("bugfix")
    verifiers = {v.id: v for v in spec.verifiers}

    assert verifiers["patch-guard"].required
    assert verifiers["repair-report"].required

    repair = spec.step("repair")
    assert repair is not None
    assert "patch-guard" in repair.verify
    assert repair.max_attempts > 1, "the repair loop must be able to repeat"

    # The step that made the change is not the step that certifies it.
    checkpoint = spec.step("verification")
    assert checkpoint is not None and checkpoint.agent is None
    assert {"tests", "patch-guard", "repair-report"} <= set(checkpoint.verify)

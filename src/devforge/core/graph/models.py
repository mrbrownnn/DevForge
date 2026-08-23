"""Task graph: explicit dependencies, artifact contracts, no swarm.

A multi-agent run here is a **directed acyclic graph declared in YAML**, not a set
of agents talking to each other. Two consequences, both deliberate:

* **The topology is fixed before anything runs.** Who runs, in what order, and what
  each one needs is visible in the workflow file and printable with
  ``devforge graph``. Nothing decides at runtime to spawn another agent.
* **Agents communicate through artifacts, never conversation.** A node declares
  what it ``produces`` and what it ``consumes``; the supervisor passes file
  references and a manifest, not transcripts. Free-form agent-to-agent chat is an
  unbounded channel with no audit trail and no schema - it is exactly the design
  this module exists to avoid.

Conditions are a closed vocabulary (``success(node)``, ``failed(node)``,
``artifact_exists(name)``, ``always``) evaluated by a matcher, not by ``eval``. A
workflow file is data; letting it evaluate expressions would make it code, and it
comes from the same place skills come from.
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from devforge.core.workflow.spec import StepKind, WorkflowSpec, WorkflowStep


class NodeStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    AWAITING_APPROVAL = "awaiting_approval"

    @property
    def finished(self) -> bool:
        return self in {
            NodeStatus.PASSED,
            NodeStatus.FAILED,
            NodeStatus.SKIPPED,
            NodeStatus.BLOCKED,
        }


class ArtifactSpec(BaseModel):
    """A file one node produces and others may consume.

    The name is the contract. A downstream node asking for ``review.json`` gets the
    path the producer actually wrote, or the run fails - it never gets a summary of
    what another agent said.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    #: Path relative to the workspace. Defaults to the artifact directory of the run.
    path: str = ""
    description: str = ""
    #: A missing optional artifact does not block a consumer.
    required: bool = True
    #: Advisory: json, markdown, patch, text.
    format: str = "text"

    @property
    def target(self) -> str:
        return self.path or self.name


CONDITION_PATTERN = re.compile(
    r"^(?P<kind>success|failed|skipped|artifact_exists|falsification_failed"
    r"|falsification_survived|always)"
    r"(?:\(\s*(?P<argument>[A-Za-z0-9_.\-/]+)\s*\))?$"
)


class Condition(BaseModel):
    """A closed-vocabulary guard on a node.

    Deliberately not an expression language. ``eval`` on a string from a workflow
    file would make the file executable, and workflow files arrive from the same
    places skills do.
    """

    model_config = ConfigDict(extra="forbid")

    expression: str = "always"

    @model_validator(mode="after")
    def _parseable(self) -> Condition:
        if not CONDITION_PATTERN.match(self.expression.strip()):
            raise ValueError(
                f"unsupported condition {self.expression!r}; allowed: always, "
                "success(node), failed(node), skipped(node), artifact_exists(name), "
                "falsification_failed(node), falsification_survived(node)"
            )
        return self

    @property
    def kind(self) -> str:
        match = CONDITION_PATTERN.match(self.expression.strip())
        assert match is not None
        return match.group("kind")

    @property
    def argument(self) -> str | None:
        match = CONDITION_PATTERN.match(self.expression.strip())
        assert match is not None
        return match.group("argument")

    def evaluate(
        self,
        statuses: dict[str, NodeStatus],
        artifacts: set[str],
        falsification: dict[str, str] | None = None,
    ) -> bool:
        """Evaluate the guard against what has happened so far.

        ``falsification`` maps a node id to that node's falsification status. It is
        separate from ``statuses`` because the two answer different questions: a
        falsify node that found a counterexample did its job correctly *and* failed
        the step, so ``failed(node)`` and ``falsification_failed(node)`` are not
        interchangeable and a workflow needs to be able to say which it means.
        """
        kind, argument = self.kind, self.argument
        if kind == "always":
            return True
        if kind == "artifact_exists":
            return argument in artifacts
        if kind in {"falsification_failed", "falsification_survived"}:
            recorded = (falsification or {}).get(argument or "")
            if recorded is None:
                return False
            wanted = "failed" if kind == "falsification_failed" else "survived"
            return recorded == wanted
        status = statuses.get(argument or "")
        if status is None:
            return False
        return {
            "success": status is NodeStatus.PASSED,
            "failed": status is NodeStatus.FAILED,
            "skipped": status is NodeStatus.SKIPPED,
        }[kind]


class TaskNode(BaseModel):
    """One unit of work in the graph. A thin wrapper over a workflow step."""

    model_config = ConfigDict(extra="forbid")

    step: WorkflowStep
    depends_on: list[str] = Field(default_factory=list)
    produces: list[ArtifactSpec] = Field(default_factory=list)
    consumes: list[str] = Field(default_factory=list)
    condition: Condition = Field(default_factory=Condition)

    @property
    def id(self) -> str:
        return self.step.id

    @property
    def agent(self) -> str | None:
        return self.step.agent

    @property
    def produced_names(self) -> list[str]:
        return [artifact.name for artifact in self.produces]


class TaskGraph(BaseModel):
    """A validated DAG over workflow steps."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    nodes: list[TaskNode]

    @model_validator(mode="after")
    def _validate(self) -> TaskGraph:
        ids = [node.id for node in self.nodes]
        duplicates = {node_id for node_id in ids if ids.count(node_id) > 1}
        if duplicates:
            raise ValueError(f"graph '{self.name}': duplicate node id(s) {sorted(duplicates)}")

        known = set(ids)
        for node in self.nodes:
            missing = [parent for parent in node.depends_on if parent not in known]
            if missing:
                raise ValueError(f"node '{node.id}' depends on unknown node(s) {missing}")
            if node.id in node.depends_on:
                raise ValueError(f"node '{node.id}' depends on itself")
            argument = node.condition.argument
            checks_node = {
                "success",
                "failed",
                "skipped",
                "falsification_failed",
                "falsification_survived",
            }
            if node.condition.kind in checks_node and argument not in known:
                raise ValueError(
                    f"node '{node.id}': condition references unknown node '{argument}'"
                )

        # Every consumed artifact must be produced by something upstream, or the
        # graph promises a channel it cannot deliver.
        produced: dict[str, str] = {}
        for node in self.nodes:
            for artifact in node.produces:
                if artifact.name in produced:
                    raise ValueError(
                        f"artifact '{artifact.name}' is produced by both "
                        f"'{produced[artifact.name]}' and '{node.id}'"
                    )
                produced[artifact.name] = node.id
        for node in self.nodes:
            for name in node.consumes:
                if name not in produced:
                    raise ValueError(f"node '{node.id}' consumes '{name}', which no node produces")

        self.levels()  # raises on a cycle
        return self

    def node(self, node_id: str) -> TaskNode | None:
        return next((node for node in self.nodes if node.id == node_id), None)

    def producer_of(self, artifact: str) -> str | None:
        for node in self.nodes:
            if artifact in node.produced_names:
                return node.id
        return None

    def levels(self) -> list[list[TaskNode]]:
        """Nodes grouped into waves that may run together.

        Everything in one level is independent of everything else in it, which is
        exactly what makes parallel execution safe rather than hopeful.
        """
        remaining = {node.id: set(node.depends_on) for node in self.nodes}
        by_id = {node.id: node for node in self.nodes}
        waves: list[list[TaskNode]] = []

        while remaining:
            ready = sorted(node_id for node_id, parents in remaining.items() if not parents)
            if not ready:
                raise ValueError(f"graph '{self.name}': dependency cycle among {sorted(remaining)}")
            waves.append([by_id[node_id] for node_id in ready])
            for node_id in ready:
                del remaining[node_id]
            for parents in remaining.values():
                parents.difference_update(ready)

        return waves

    @property
    def parallel_width(self) -> int:
        return max((len(level) for level in self.levels()), default=0)

    def describe(self) -> str:
        lines = [f"{self.name}: {len(self.nodes)} nodes, width {self.parallel_width}"]
        for depth, level in enumerate(self.levels()):
            names = ", ".join(
                f"{node.id}({node.agent})" if node.agent else node.id for node in level
            )
            lines.append(f"  level {depth}: {names}")
        return "\n".join(lines)


def graph_from_workflow(workflow: WorkflowSpec) -> TaskGraph:
    """Build a graph from a workflow.

    A workflow with no ``depends_on`` anywhere becomes a straight chain, so every
    existing sequential workflow keeps working unchanged and the supervisor is the
    only executor that needs to exist.
    """
    declared = any(step.depends_on for step in workflow.steps)
    nodes: list[TaskNode] = []

    for index, step in enumerate(workflow.steps):
        depends_on = list(step.depends_on)
        if not declared and index > 0:
            depends_on = [workflow.steps[index - 1].id]
        nodes.append(
            TaskNode(
                step=step,
                depends_on=depends_on,
                produces=[
                    ArtifactSpec(name=name, format=_format_of(name)) for name in step.produces
                ],
                consumes=list(step.consumes),
                condition=Condition(expression=step.when or "always"),
            )
        )

    return TaskGraph(name=workflow.name, description=workflow.description, nodes=nodes)


def _format_of(name: str) -> str:
    if name.endswith(".json"):
        return "json"
    if name.endswith((".md", ".markdown")):
        return "markdown"
    if name.endswith((".patch", ".diff")):
        return "patch"
    return "text"


def approval_nodes(graph: TaskGraph) -> list[TaskNode]:
    return [node for node in graph.nodes if node.step.kind is StepKind.APPROVAL]

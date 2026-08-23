"""The supervisor: runs a task graph, not a swarm.

It walks the graph level by level. Everything in one level is independent by
construction, so those nodes run concurrently; nothing else does. There is no
dynamic spawning, no agent deciding to call another agent, and no negotiation -
the topology was fixed when the workflow file was written.

Per node, in order:

1. **Guard** - the condition decides whether this node runs at all.
2. **Inputs** - required artifacts must exist, or the node is blocked rather than
   run on a missing input.
3. **Least privilege** - the agent gets only the tools and paths its spec grants.
4. **Execute** - through the existing step machinery: agent, verification, repair
   loop, approval gate.
5. **Outputs** - declared artifacts are captured, and a node that promised one and
   did not write it fails. Claiming is not producing.

On failure: artifacts are preserved, the failure is recorded on the task, and
downstream nodes are blocked rather than run on absent inputs. Nothing already
written is discarded.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

from devforge.core.execution import ExecutionContext
from devforge.core.graph.artifacts import ArtifactStore
from devforge.core.graph.models import Condition, NodeStatus, TaskGraph, TaskNode
from devforge.core.models import StepStatus, Task, TaskResult, TaskStatus, utcnow
from devforge.core.workflow.spec import OnFailure, WorkflowSpec
from devforge.observability.logging import RunLogger


@dataclass
class NodeOutcome:
    node_id: str
    status: NodeStatus
    reason: str = ""
    attempts: int = 0
    produced: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status is NodeStatus.PASSED


@dataclass
class GraphRunReport:
    """What the supervisor did, node by node."""

    graph: str
    outcomes: dict[str, NodeOutcome] = field(default_factory=dict)
    levels_run: int = 0
    preserved_artifacts: list[str] = field(default_factory=list)
    stopped_at: str | None = None
    reason: str = ""

    @property
    def statuses(self) -> dict[str, NodeStatus]:
        return {node_id: outcome.status for node_id, outcome in self.outcomes.items()}

    @property
    def failed(self) -> list[str]:
        return [
            node_id
            for node_id, outcome in self.outcomes.items()
            if outcome.status is NodeStatus.FAILED
        ]

    @property
    def blocked(self) -> list[str]:
        return [
            node_id
            for node_id, outcome in self.outcomes.items()
            if outcome.status is NodeStatus.BLOCKED
        ]


class Supervisor:
    """Executes a :class:`TaskGraph` using an existing orchestrator for each node.

    It delegates the *inside* of a node - agent invocation, verification, repair,
    approval - to the orchestrator that already does that well, and owns only what
    is new: ordering, concurrency, conditions, artifacts and blocking.
    """

    def __init__(self, orchestrator, *, logger: RunLogger | None = None) -> None:
        self.orchestrator = orchestrator
        self.logger = logger or orchestrator.logger
        self.store = orchestrator.store

    async def run(self, task: Task, workflow: WorkflowSpec, graph: TaskGraph) -> TaskResult:
        artifacts = ArtifactStore(root=self.store.root, run_dir=self.store.run_dir(task.task_id))
        report = GraphRunReport(graph=graph.name)

        task.status = TaskStatus.RUNNING
        self.store.save_task(task)
        levels = graph.levels()
        self.logger.info(
            "graph.start",
            task_id=task.task_id,
            graph=graph.name,
            nodes=len(graph.nodes),
            levels=len(levels),
            width=graph.parallel_width,
        )

        specs = self.orchestrator.verification.collect_specs(
            workflow, self.store.load_config().verifiers
        )
        execution = ExecutionContext(
            task=task,
            workspace=self.store.root,
            policy=self.orchestrator.policy,
            tools=self.orchestrator.tools,
            approval_gate=self.orchestrator.approvals,
            logger=self.logger,
        )

        for depth, level in enumerate(levels):
            report.levels_run = depth + 1
            runnable = [node for node in level if self._should_run(node, report, artifacts)]

            for node in level:
                if node not in runnable and node.id not in report.outcomes:
                    report.outcomes[node.id] = self._skip(node, report, artifacts)

            if not runnable:
                continue

            self.logger.info(
                "graph.level",
                # `level` is the logger's own severity field; the graph depth needs
                # a name of its own.
                depth=depth,
                running=[node.id for node in runnable],
                parallel=len(runnable) > 1,
            )

            if len(runnable) == 1:
                results = [await self._run_node(runnable[0], task, specs, execution, artifacts)]
            else:
                # Independent by construction, so concurrency is safe rather than hopeful.
                results = await asyncio.gather(
                    *(self._run_node(node, task, specs, execution, artifacts) for node in runnable)
                )

            for outcome in results:
                report.outcomes[outcome.node_id] = outcome

            fatal = [
                outcome
                for outcome in results
                if outcome.status is NodeStatus.FAILED
                and (graph.node(outcome.node_id).step.on_failure is OnFailure.FAIL)
            ]
            paused = [
                outcome for outcome in results if outcome.status is NodeStatus.AWAITING_APPROVAL
            ]

            if paused:
                report.stopped_at = paused[0].node_id
                report.reason = paused[0].reason
                return self._finish(task, report, artifacts, TaskStatus.AWAITING_APPROVAL)

            if fatal:
                report.stopped_at = fatal[0].node_id
                report.reason = fatal[0].reason
                self._block_downstream(graph, report, fatal[0].node_id)
                return self._finish(task, report, artifacts, TaskStatus.FAILED)

        return self._finish(task, report, artifacts, TaskStatus.COMPLETED)

    # -- node lifecycle ---------------------------------------------------------

    def _should_run(self, node: TaskNode, report: GraphRunReport, artifacts: ArtifactStore) -> bool:
        record = self.store  # noqa: F841 - keeps the intent explicit below
        if node.id in report.outcomes:
            return False
        if not node.condition.evaluate(report.statuses, artifacts.available):
            return False
        # A dependency that did not pass means this node would run on stale or absent
        # inputs. Blocking is the honest outcome; running anyway invents a result.
        for parent in node.depends_on:
            parent_status = report.statuses.get(parent)
            if parent_status not in {NodeStatus.PASSED, NodeStatus.SKIPPED}:
                return False
        return True

    def _skip(
        self, node: TaskNode, report: GraphRunReport, artifacts: ArtifactStore
    ) -> NodeOutcome:
        blocked_parents = [
            parent
            for parent in node.depends_on
            if report.statuses.get(parent) not in {NodeStatus.PASSED, NodeStatus.SKIPPED, None}
        ]
        if blocked_parents:
            reason = f"blocked: dependency {blocked_parents} did not pass"
            status = NodeStatus.BLOCKED
        elif not node.condition.evaluate(report.statuses, artifacts.available):
            reason = f"condition '{node.condition.expression}' was not met"
            status = NodeStatus.SKIPPED
        else:
            reason = "dependency has not run"
            status = NodeStatus.BLOCKED

        self.logger.info("graph.node_skipped", node=node.id, status=status.value, reason=reason)
        return NodeOutcome(node_id=node.id, status=status, reason=reason)

    async def _run_node(
        self,
        node: TaskNode,
        task: Task,
        specs: dict,
        execution: ExecutionContext,
        artifacts: ArtifactStore,
    ) -> NodeOutcome:
        missing_inputs = artifacts.missing(
            [name for name in node.consumes if self._is_required(node, name)]
        )
        if missing_inputs:
            reason = f"required input artifact(s) {missing_inputs} were not produced"
            self.logger.error("graph.node_blocked", node=node.id, reason=reason)
            task.add_error("graph", reason, step_id=node.id)
            return NodeOutcome(node_id=node.id, status=NodeStatus.BLOCKED, reason=reason)

        record = task.ensure_step(node.id, kind=node.step.kind.value, agent=node.agent)
        manifest = artifacts.manifest(node.consumes)

        self.logger.info(
            "graph.node_start",
            node=node.id,
            agent=node.agent,
            consumes=node.consumes or None,
            produces=node.produced_names or None,
        )

        outcome = await self.orchestrator.run_step(
            task=task,
            step=node.step,
            record=record,
            specs=specs,
            execution=execution,
            artifact_manifest=manifest,
        )

        if outcome is not None and task.status is TaskStatus.AWAITING_APPROVAL:
            return NodeOutcome(
                node_id=node.id,
                status=NodeStatus.AWAITING_APPROVAL,
                reason=outcome.reason,
                attempts=record.attempt_count,
            )

        if record.status is not StepStatus.PASSED:
            reason = record.error or f"node '{node.id}' did not pass"
            return NodeOutcome(
                node_id=node.id,
                status=NodeStatus.FAILED,
                reason=reason,
                attempts=record.attempt_count,
            )

        produced, missing = self._capture_outputs(node, artifacts)
        if missing:
            reason = (
                f"declared artifact(s) {missing} were not written. An agent claiming "
                "to have produced something is not evidence that it did."
            )
            record.status = StepStatus.FAILED
            record.error = reason
            task.add_error("artifact", reason, step_id=node.id)
            self.store.save_task(task)
            self.logger.error("graph.artifact_missing", node=node.id, missing=missing)
            return NodeOutcome(
                node_id=node.id,
                status=NodeStatus.FAILED,
                reason=reason,
                attempts=record.attempt_count,
                produced=produced,
                missing=missing,
            )

        self.logger.info(
            "graph.node_finish",
            node=node.id,
            status="passed",
            attempts=record.attempt_count,
            produced=produced or None,
        )
        return NodeOutcome(
            node_id=node.id,
            status=NodeStatus.PASSED,
            attempts=record.attempt_count,
            produced=produced,
        )

    @staticmethod
    def _is_required(node: TaskNode, name: str) -> bool:
        return True

    def _capture_outputs(
        self, node: TaskNode, artifacts: ArtifactStore
    ) -> tuple[list[str], list[str]]:
        produced: list[str] = []
        missing: list[str] = []
        for spec in node.produces:
            path = artifacts.resolve(spec.name, spec.path)
            record = artifacts.capture(spec.name, path, producer=node.id, fmt=spec.format)
            if record.missing:
                if spec.required:
                    missing.append(spec.name)
            else:
                produced.append(spec.name)
        return produced, missing

    def _block_downstream(self, graph: TaskGraph, report: GraphRunReport, failed: str) -> None:
        """Mark everything that depended on a failure, rather than leaving it unexplained."""
        changed = True
        blocked = {failed}
        while changed:
            changed = False
            for node in graph.nodes:
                if node.id in report.outcomes:
                    continue
                if set(node.depends_on) & blocked:
                    report.outcomes[node.id] = NodeOutcome(
                        node_id=node.id,
                        status=NodeStatus.BLOCKED,
                        reason=f"blocked by failure of '{failed}'",
                    )
                    blocked.add(node.id)
                    changed = True

    def _finish(
        self,
        task: Task,
        report: GraphRunReport,
        artifacts: ArtifactStore,
        status: TaskStatus,
    ) -> TaskResult:
        if status is TaskStatus.FAILED:
            # Preserve first: work that reached disk must survive the step that failed.
            destination = self.store.run_dir(task.task_id) / "preserved"
            report.preserved_artifacts = artifacts.preserve(destination)
            if report.preserved_artifacts:
                self.logger.info(
                    "graph.artifacts_preserved",
                    node=report.stopped_at,
                    artifacts=report.preserved_artifacts,
                    destination=str(destination),
                )

        task.status = status
        if status is TaskStatus.COMPLETED:
            task.current_step = None
        task.context["graph"] = {
            "name": report.graph,
            "levels_run": report.levels_run,
            "nodes": {
                node_id: outcome.status.value for node_id, outcome in report.outcomes.items()
            },
            "artifacts": artifacts.summary(),
            "preserved": report.preserved_artifacts,
        }
        task.touch()
        self.store.save_task(task)

        self.logger.info(
            "graph.finish",
            task_id=task.task_id,
            status=status.value,
            failed=report.failed or None,
            blocked=report.blocked or None,
            artifacts=len(artifacts.available),
        )

        reason = report.reason or (
            "graph completed" if status is TaskStatus.COMPLETED else "graph stopped"
        )
        result = TaskResult.from_task(task, stopped_at=report.stopped_at, reason=reason)
        return result


def condition_always() -> Condition:
    return Condition(expression="always")


def node_started_at() -> str:
    return utcnow().isoformat()


def graph_summary(report: GraphRunReport) -> str:
    parts = [f"{node_id}={outcome.status.value}" for node_id, outcome in report.outcomes.items()]
    return ", ".join(parts)


def workspace_of(store) -> Path:
    return Path(store.root)

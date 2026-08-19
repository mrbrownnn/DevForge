"""Application wiring.

One place builds the object graph - registries, policy, runtime, logger, store -
so the CLI, the tests and any future server share identical construction and no
module reaches for a global singleton.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from devforge.agents.spec import AgentRegistry
from devforge.approval.gate import ApprovalGate, Prompter
from devforge.core.orchestrator.engine import Orchestrator
from devforge.core.registry.skills import SkillRegistry
from devforge.core.state.store import ProjectConfig, ProjectStore
from devforge.core.workflow.loader import WorkflowLoader
from devforge.observability.logging import EventSink, RunLogger, jsonl_sink
from devforge.policy.engine import PolicyEngine
from devforge.runtime.base import AgentRuntime
from devforge.runtime.registry import RuntimeRegistry
from devforge.tools.base import ToolRegistry
from devforge.verification.engine import VerificationEngine


@dataclass
class AppContext:
    """Everything a command needs, constructed once."""

    store: ProjectStore
    config: ProjectConfig
    policy: PolicyEngine
    workflows: WorkflowLoader
    skills: SkillRegistry
    agents: AgentRegistry
    tools: ToolRegistry
    runtimes: RuntimeRegistry
    verification: VerificationEngine
    logger: RunLogger

    @classmethod
    def load(
        cls,
        root: Path | None = None,
        *,
        extra_sinks: list[EventSink] | None = None,
    ) -> AppContext:
        store = ProjectStore.discover(root)
        config = store.load_config()
        return cls(
            store=store,
            config=config,
            policy=PolicyEngine.load(store.root, workspace=store.root),
            workflows=WorkflowLoader.for_project(store.root),
            skills=SkillRegistry.discover(store.root),
            agents=AgentRegistry.discover(store.root),
            tools=ToolRegistry.default(),
            runtimes=RuntimeRegistry.default(),
            verification=VerificationEngine(),
            logger=RunLogger(list(extra_sinks or []), project_id=config.project_id),
        )

    # -- helpers ----------------------------------------------------------------

    def runtime(self, name: str | None = None) -> AgentRuntime:
        return self.runtimes.create(name or self.config.default_runtime)

    def run_logger(self, task_id: str, *, extra_sinks: list[EventSink] | None = None) -> RunLogger:
        """A logger bound to one run, writing to that run's events.jsonl."""
        logger = self.logger.bind(task_id=task_id)
        logger.add_sink(jsonl_sink(self.store.events_path(task_id)))
        for sink in extra_sinks or []:
            logger.add_sink(sink)
        return logger

    def orchestrator(
        self,
        *,
        runtime: AgentRuntime,
        logger: RunLogger,
        prompter: Prompter | None = None,
    ) -> Orchestrator:
        return Orchestrator(
            store=self.store,
            runtime=runtime,
            tools=self.tools,
            skills=self.skills,
            agents=self.agents,
            verification=self.verification,
            approvals=ApprovalGate(self.policy, prompter=prompter),
            policy=self.policy,
            logger=logger,
            workspace=self.store.root,
        )

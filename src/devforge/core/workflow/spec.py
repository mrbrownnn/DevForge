"""Declarative workflow model.

A workflow is data, not code: it names an ordered list of steps, each of which is
one of three kinds.

``agent``
    Invoke an agent through the runtime, optionally followed by verification and
    a bounded repair loop.
``verify``
    Run verifiers only - a checkpoint with no agent.
``approval``
    Pause for a human decision at a named gate.

Verifiers are declared once (in the workflow's ``verifiers:`` block or in the
project config) and referenced by id from steps, so adding a new check never
requires touching Python.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

DEFAULT_MAX_ATTEMPTS = 3


class StepKind(str, Enum):
    AGENT = "agent"
    VERIFY = "verify"
    APPROVAL = "approval"


class OnFailure(str, Enum):
    """What the orchestrator does when a step exhausts its attempts."""

    FAIL = "fail"  # stop the run (default)
    CONTINUE = "continue"  # record the failure and move on


class VerifierSpec(BaseModel):
    """An executable check.

    ``argv`` is an argument vector, never a shell string: DevForge never spawns a
    shell, so quoting bugs cannot become command injection.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str = "command"
    description: str = ""
    argv: list[str] = Field(default_factory=list)
    cwd: str | None = None
    #: Files an artifact verifier expects to exist; ignored by command verifiers.
    expect: list[str] = Field(default_factory=list)
    timeout_s: int = 600
    required: bool = True
    #: Kind-specific configuration. Deliberately opaque to the orchestrator: a
    #: verifier kind that needs settings (the visual verifier needs a reference URL
    #: and a candidate URL) reads them here, and the core keeps knowing nothing about
    #: any particular kind.
    params: dict[str, Any] = Field(default_factory=dict)
    # Exit codes other than 0 that still count as success (e.g. "no tests collected").
    success_exit_codes: list[int] = Field(default_factory=lambda: [0])

    @model_validator(mode="after")
    def _check(self) -> VerifierSpec:
        if self.kind == "command" and not self.argv:
            raise ValueError(f"verifier '{self.id}': command verifiers require 'argv'")
        if self.kind == "artifacts" and self.argv:
            raise ValueError(
                f"verifier '{self.id}': artifact verifiers take 'expect', not 'argv' - "
                "they must never execute anything"
            )
        return self


class WorkflowStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str = ""
    kind: StepKind = StepKind.AGENT
    description: str = ""

    # agent steps
    agent: str | None = None
    skills: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    prompt: str = ""
    outputs: list[str] = Field(default_factory=list)

    # verification (valid on agent and verify steps)
    verify: list[str] = Field(default_factory=list)
    max_attempts: int = DEFAULT_MAX_ATTEMPTS

    # approval steps
    gate: str | None = None

    # -- task graph (Phase 5) --------------------------------------------------
    #: Nodes that must finish before this one starts. Empty means "after the
    #: previous step", so existing sequential workflows are unchanged.
    depends_on: list[str] = Field(default_factory=list)
    #: Artifacts this step writes. Downstream steps consume these by name - that is
    #: the only channel between agents; there is no agent-to-agent conversation.
    produces: list[str] = Field(default_factory=list)
    #: Artifacts this step needs. Every one must be produced by some other node.
    consumes: list[str] = Field(default_factory=list)
    #: Guard from a closed vocabulary: always, success(node), failed(node),
    #: skipped(node), artifact_exists(name). Never an evaluated expression.
    when: str = ""

    on_failure: OnFailure = OnFailure.FAIL

    @model_validator(mode="after")
    def _check(self) -> WorkflowStep:
        if self.kind is StepKind.AGENT and not self.agent:
            raise ValueError(f"step '{self.id}': agent steps require an 'agent'")
        if self.kind is StepKind.APPROVAL and not self.gate:
            raise ValueError(f"step '{self.id}': approval steps require a 'gate'")
        if self.kind is StepKind.APPROVAL and (self.verify or self.agent):
            raise ValueError(f"step '{self.id}': approval steps take no agent or verifiers")
        if self.kind is StepKind.VERIFY and not self.verify:
            raise ValueError(f"step '{self.id}': verify steps require at least one verifier")
        if self.max_attempts < 1:
            raise ValueError(f"step '{self.id}': max_attempts must be >= 1")
        if not self.name:
            self.name = self.id.replace("-", " ").replace("_", " ").title()
        if self.consumes and self.kind is StepKind.APPROVAL:
            raise ValueError(f"step '{self.id}': an approval step consumes no artifacts")
        # `outputs` predates the graph and `produces` came with it; they are one
        # concept. Mirroring both ways keeps a single source of truth - the runtime
        # reads `outputs`, the supervisor reads `produces`, and a step that set only
        # one would otherwise be invisible to the other.
        if self.outputs and not self.produces:
            self.produces = list(self.outputs)
        elif self.produces and not self.outputs:
            self.outputs = list(self.produces)
        elif self.outputs and self.produces and set(self.outputs) != set(self.produces):
            raise ValueError(
                f"step '{self.id}': 'outputs' and 'produces' name the same artifacts; "
                "declaring two different lists is ambiguous - use one"
            )
        return self

    @property
    def repairable(self) -> bool:
        """Only agent steps with verifiers can be repaired by re-invoking the agent."""
        return self.kind is StepKind.AGENT and bool(self.verify)


class WorkflowSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str = "1.0.0"
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    verifiers: list[VerifierSpec] = Field(default_factory=list)
    steps: list[WorkflowStep]
    source_path: str | None = None

    @model_validator(mode="after")
    def _check(self) -> WorkflowSpec:
        if not self.steps:
            raise ValueError(f"workflow '{self.name}': must declare at least one step")
        seen: set[str] = set()
        for step in self.steps:
            if step.id in seen:
                raise ValueError(f"workflow '{self.name}': duplicate step id '{step.id}'")
            seen.add(step.id)
        vids: set[str] = set()
        for verifier in self.verifiers:
            if verifier.id in vids:
                raise ValueError(f"workflow '{self.name}': duplicate verifier id '{verifier.id}'")
            vids.add(verifier.id)
        return self

    def step(self, step_id: str) -> WorkflowStep | None:
        return next((s for s in self.steps if s.id == step_id), None)

    def index_of(self, step_id: str) -> int:
        for index, step in enumerate(self.steps):
            if step.id == step_id:
                return index
        raise KeyError(step_id)

    def referenced_verifiers(self) -> set[str]:
        return {vid for step in self.steps for vid in step.verify}

    def missing_verifiers(self, available: set[str]) -> set[str]:
        """Verifier ids referenced by steps that nothing defines."""
        return self.referenced_verifiers() - (available | {v.id for v in self.verifiers})

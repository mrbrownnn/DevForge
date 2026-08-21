"""Prompt composition.

Turns (agent spec + workflow step + task + skills + project memory) into an
:class:`AgentInvocation`. Templates use ``{{placeholder}}`` substitution rather
than ``str.format`` so that prose containing braces (JSON examples, code) never
breaks rendering, and an unknown placeholder is left visible instead of raising.

Keeping this in one module is what lets prompts live in YAML/Markdown instead of
being scattered through the orchestrator.
"""

from __future__ import annotations

import re
from typing import Any

from devforge.agents.spec import AgentSpec
from devforge.core.models import AgentInvocation, InvocationMode, StepAttempt, Task
from devforge.core.registry.skills import Skill
from devforge.core.workflow.spec import WorkflowStep

_PLACEHOLDER = re.compile(r"\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}")

MAX_DIAGNOSTIC_CHARS = 4000


def render_template(template: str, values: dict[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in values:
            return match.group(0)
        return str(values[key])

    return _PLACEHOLDER.sub(replace, template)


def format_skills(skills: list[Skill]) -> str:
    if not skills:
        return "(no skills attached)"
    blocks = []
    for skill in skills:
        blocks.append(f"## Skill: {skill.name} (v{skill.version})\n\n{skill.instructions}".strip())
    return "\n\n".join(blocks)


def format_memory(memory: dict[str, str]) -> str:
    if not memory:
        return "(no project memory recorded)"
    return "\n\n".join(f"### {name}\n\n{content.strip()}" for name, content in memory.items())


def format_diagnostics(attempt: StepAttempt | None) -> str:
    """Render the previous attempt's failing verifiers as a repair briefing."""
    if attempt is None:
        return ""
    failures = attempt.failed_verifiers
    if not failures:
        return ""
    lines = ["The previous attempt failed verification. Fix the root cause, do not mask it.", ""]
    for result in failures:
        lines.append(f"- verifier '{result.verifier}' ({result.kind}): {result.status.value}")
        if result.exit_code is not None:
            lines.append(f"  exit code: {result.exit_code}")
        if result.summary:
            lines.append(f"  summary: {result.summary}")
        if result.output_excerpt:
            excerpt = result.output_excerpt[:MAX_DIAGNOSTIC_CHARS]
            lines.append(f"  output:\n{_indent(excerpt)}")
    return "\n".join(lines)


def _indent(text: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())


DEFAULT_PROMPT_TEMPLATE = """\
# Task

{{task_description}}

## Workflow step

{{step_id}} - {{step_description}}

## Project memory

{{memory}}

## Skills

{{skills}}
"""


def build_invocation(
    *,
    task: Task,
    step: WorkflowStep,
    agent: AgentSpec,
    skills: list[Skill],
    memory: dict[str, str],
    tools: list[str],
    context_pack: str = "",
    attempt: int = 1,
    previous_attempt: StepAttempt | None = None,
    workspace: str = ".",
) -> AgentInvocation:
    diagnostics = format_diagnostics(previous_attempt)
    mode = InvocationMode.REPAIR if diagnostics else InvocationMode.INITIAL

    values: dict[str, Any] = {
        "task_id": task.task_id,
        "task_description": task.description,
        "workflow": task.workflow,
        "step_id": step.id,
        "step_name": step.name,
        "step_description": step.description or step.name,
        "step_prompt": step.prompt,
        "agent": agent.name,
        "role": agent.role,
        "attempt": attempt,
        "skills": format_skills(skills),
        # A retrieved pack replaces the whole-memory dump when one is available:
        # same slot in the template, a fraction of the tokens, and scoped to the task.
        "memory": context_pack.strip() or format_memory(memory),
        "diagnostics": diagnostics,
        "outputs": ", ".join(step.outputs) or "(none declared)",
        "tools": ", ".join(tools) or "(none)",
    }

    body_template = agent.prompt_template or DEFAULT_PROMPT_TEMPLATE
    prompt = render_template(body_template, values)
    if step.prompt:
        prompt = f"{prompt}\n\n## Step instructions\n\n{step.prompt}"
    if diagnostics:
        repair_template = agent.repair_template or "## Repair briefing\n\n{{diagnostics}}"
        prompt = f"{prompt}\n\n{render_template(repair_template, values)}"

    return AgentInvocation(
        task_id=task.task_id,
        step_id=step.id,
        agent=agent.name,
        role=agent.role,
        mode=mode,
        attempt=attempt,
        system_prompt=render_template(agent.system_prompt, values),
        prompt=prompt.strip(),
        context={"workflow": task.workflow, "outputs": step.outputs},
        skills=[skill.name for skill in skills],
        tools=tools,
        workspace=workspace,
        timeout_s=agent.timeout_s,
    )

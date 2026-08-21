"""Tool descriptors: what a tool is, needs, accepts, returns, and how bad it can be.

Every tool declares one of these. It serves four purposes:

1. **Permission mapping.** ``permissions`` states what the tool needs before it is
   ever invoked, so a runtime can be given least privilege and a reviewer can see
   the blast radius without reading the implementation.
2. **Input validation.** Parameters are checked against ``input_schema`` at the
   boundary, so a malformed or hostile call is rejected before any handler runs.
3. **Risk classification.** ``risk`` drives approval requirements - the policy
   engine decides, but the descriptor is what it decides about.
4. **Discoverability.** MCP tools arrive as JSON schemas from an untrusted server;
   giving native tools the same shape means one validation path, not two.

The schema language is a deliberately small subset of JSON Schema: ``type``,
``properties``, ``required``, ``items``, ``enum``. MCP servers publish full JSON
Schema and we validate only what we understand - unknown keywords are ignored
rather than silently treated as satisfied. That limitation is documented in
docs/tools.md rather than papered over.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(str, Enum):
    """How much damage a successful call can do."""

    #: Reads data that is already inside the workspace.
    READ = "read"
    #: Writes inside the workspace. Recoverable with version control.
    WRITE = "write"
    #: Executes code, reaches the network, or leaves the workspace.
    EXECUTE = "execute"
    #: Irreversible or outward-facing: deletes, pushes, deploys, publishes.
    DESTRUCTIVE = "destructive"

    @property
    def requires_approval_by_default(self) -> bool:
        return self is RiskLevel.DESTRUCTIVE


class ToolPermissions(BaseModel):
    """What a tool needs. A tool that asks for nothing can be given nothing."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    filesystem_read: bool = False
    filesystem_write: bool = False
    filesystem_delete: bool = False
    process_execution: bool = False
    network: bool = False
    #: Names of approval gates this tool may trigger.
    gates: list[str] = Field(default_factory=list)

    def summary(self) -> str:
        granted = [
            name
            for name, value in (
                ("fs:read", self.filesystem_read),
                ("fs:write", self.filesystem_write),
                ("fs:delete", self.filesystem_delete),
                ("exec", self.process_execution),
                ("net", self.network),
            )
            if value
        ]
        return ", ".join(granted) or "none"


class ToolDescriptor(BaseModel):
    """The public contract of a tool."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    version: str = "1.0.0"
    description: str = ""
    capabilities: list[str] = Field(default_factory=list)
    permissions: ToolPermissions = Field(default_factory=ToolPermissions)
    #: action name -> JSON-Schema-subset object describing its parameters
    input_schema: dict[str, dict[str, Any]] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    risk: RiskLevel = RiskLevel.READ
    #: Where the tool comes from: "builtin" or "mcp:<server>".
    origin: str = "builtin"

    @property
    def actions(self) -> tuple[str, ...]:
        return tuple(self.input_schema)

    def schema_for(self, action: str) -> dict[str, Any] | None:
        return self.input_schema.get(action)


#: The result shape every tool returns, published so callers do not have to guess.
TOOL_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "tool": {"type": "string"},
        "action": {"type": "string"},
        "status": {"type": "string", "enum": ["ok", "error", "denied", "unavailable"]},
        "output": {"type": "string"},
        "error": {"type": "string"},
        "data": {"type": "object"},
        "duration_ms": {"type": "integer"},
    },
    "required": ["tool", "action", "status"],
}


# --------------------------------------------------------------------------- validation

_TYPES: dict[str, type | tuple[type, ...]] = {
    "string": str,
    "number": (int, float),
    "integer": int,
    "boolean": bool,
    "array": list,
    "object": dict,
}


def validate_params(schema: dict[str, Any] | None, params: dict[str, Any]) -> list[str]:
    """Validate call parameters against a schema subset. Returns a list of problems.

    Unknown JSON Schema keywords are ignored rather than assumed satisfied: this
    validator narrows the input surface, it does not certify it.
    """
    if not schema:
        return []

    problems: list[str] = []
    properties: dict[str, Any] = schema.get("properties", {}) or {}
    required: list[str] = schema.get("required", []) or []

    for name in required:
        if params.get(name) is None:
            problems.append(f"missing required parameter '{name}'")

    if schema.get("additionalProperties") is False:
        for name in params:
            if name not in properties:
                problems.append(f"unexpected parameter '{name}'")

    for name, value in params.items():
        rules = properties.get(name)
        if not isinstance(rules, dict) or value is None:
            continue
        problems.extend(_check_value(name, value, rules))

    return problems


def _check_value(name: str, value: Any, rules: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    expected = rules.get("type")

    if isinstance(expected, str) and expected in _TYPES:
        python_type = _TYPES[expected]
        # bool is a subclass of int; a boolean is not an acceptable integer here.
        if expected in {"integer", "number"} and isinstance(value, bool):
            problems.append(f"parameter '{name}' must be {expected}, got boolean")
        elif not isinstance(value, python_type):
            problems.append(f"parameter '{name}' must be {expected}, got {type(value).__name__}")
            return problems

    choices = rules.get("enum")
    if isinstance(choices, list) and value not in choices:
        problems.append(f"parameter '{name}' must be one of {choices}")

    if isinstance(value, str):
        maximum = rules.get("maxLength")
        if isinstance(maximum, int) and len(value) > maximum:
            problems.append(f"parameter '{name}' exceeds maxLength {maximum}")

    if isinstance(value, list):
        item_rules = rules.get("items")
        if isinstance(item_rules, dict):
            for index, item in enumerate(value):
                problems.extend(_check_value(f"{name}[{index}]", item, item_rules))

    # A nested object is validated by the same rules as a top-level one. Without
    # this, a schema that declares a closed vocabulary inside a list (the browser
    # tool's interaction steps) would accept anything, and the descriptor would be
    # documenting a constraint it does not enforce.
    if isinstance(value, dict) and _describes_object(rules):
        problems.extend(f"{name}.{problem}" for problem in validate_params(rules, value))

    return problems


def _describes_object(rules: dict[str, Any]) -> bool:
    return bool(
        rules.get("properties")
        or rules.get("required")
        or rules.get("additionalProperties") is False
    )

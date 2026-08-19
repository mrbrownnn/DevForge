"""MCP server configuration, discovery and trust.

An MCP server is a third party that DevForge starts as a child process and then
takes instructions from. It is exactly as untrusted as a third-party skill, and
the same rule applies: **nothing is trusted because it is configured.**

Configuration lives in ``.devforge/mcp.yaml``:

```yaml
version: 1
servers:
  - name: filesystem
    command: [npx, -y, "@modelcontextprotocol/server-filesystem", "./src"]
    transport: stdio          # the only transport implemented
    enabled: true
    trust: untrusted          # untrusted | reviewed
    allow_tools: [read_file]   # empty means "none until named"
    timeout_s: 30
    allow_env: []              # extra env vars this server may inherit
    risk: read                 # read | write | execute | destructive
```

Three rules make this safe to have at all:

1. **Servers are disabled until enabled**, and starting one is a subprocess spawn,
   so the command itself goes through the shell allowlist.
2. **Tools are denied until named** in ``allow_tools``. A server that grows a new
   tool overnight cannot use it; discovery reports it as unapproved.
3. **Trust is recorded, not inferred.** A ``reviewed`` server is one a human wrote
   down as reviewed; nothing promotes itself.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from devforge.core.errors import ConfigError
from devforge.tools.descriptor import RiskLevel

MCP_CONFIG_FILENAME = "mcp.yaml"


class Transport(str, Enum):
    STDIO = "stdio"
    #: Declared so a config naming it fails loudly instead of being misread as stdio.
    HTTP = "http"
    SSE = "sse"


class ServerTrust(str, Enum):
    UNTRUSTED = "untrusted"
    REVIEWED = "reviewed"


class McpServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    command: list[str] = Field(default_factory=list)
    transport: Transport = Transport.STDIO
    enabled: bool = False
    trust: ServerTrust = ServerTrust.UNTRUSTED
    #: Tools this server is permitted to expose. Empty means none.
    allow_tools: list[str] = Field(default_factory=list)
    timeout_s: float = 30.0
    allow_env: list[str] = Field(default_factory=list)
    risk: RiskLevel = RiskLevel.EXECUTE
    description: str = ""

    @model_validator(mode="after")
    def _check(self) -> McpServerConfig:
        if not self.name.strip():
            raise ValueError("an MCP server needs a name")
        if self.transport is Transport.STDIO and not self.command:
            raise ValueError(f"server '{self.name}': stdio transport requires a 'command'")
        if self.timeout_s <= 0:
            raise ValueError(f"server '{self.name}': timeout_s must be positive")
        return self

    @property
    def supported(self) -> bool:
        return self.transport is Transport.STDIO

    def permits(self, tool_name: str) -> bool:
        return tool_name in self.allow_tools


class McpConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    servers: list[McpServerConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_names(self) -> McpConfig:
        seen: set[str] = set()
        for server in self.servers:
            if server.name in seen:
                raise ValueError(f"duplicate MCP server name '{server.name}'")
            seen.add(server.name)
        return self

    def server(self, name: str) -> McpServerConfig | None:
        return next((s for s in self.servers if s.name == name), None)

    @property
    def enabled_servers(self) -> list[McpServerConfig]:
        return [s for s in self.servers if s.enabled and s.supported]


def config_path(project_root: Path) -> Path:
    return Path(project_root) / ".devforge" / MCP_CONFIG_FILENAME


def load_config(project_root: Path | None) -> McpConfig:
    """Load MCP configuration. A project with no config file has no MCP servers."""
    if project_root is None:
        return McpConfig()
    path = config_path(project_root)
    if not path.is_file():
        return McpConfig()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: MCP config must be a YAML mapping")
    try:
        return McpConfig.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in error['loc'])}: {error['msg']}" for error in exc.errors()
        )
        raise ConfigError(f"{path}: {problems}") from exc


EXAMPLE_CONFIG = """\
# MCP servers available to this project.
#
# Nothing here is trusted by being listed. A server must be enabled explicitly, its
# command passes the shell allowlist like any other subprocess, and each tool must be
# named in allow_tools before it can be called. See docs/security/mcp.md.
version: 1
servers: []
#  - name: filesystem
#    command: [npx, -y, "@modelcontextprotocol/server-filesystem", "./src"]
#    transport: stdio
#    enabled: false
#    trust: untrusted
#    allow_tools: []      # deny-by-default: name each tool you actually want
#    timeout_s: 30
#    risk: read
"""

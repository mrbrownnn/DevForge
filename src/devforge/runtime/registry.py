"""Runtime registry.

Runtimes are registered as zero-argument factories so that constructing one (which
may probe the filesystem or spawn a version check) is deferred until a run
actually needs it.
"""

from __future__ import annotations

from collections.abc import Callable

from devforge.core.registry.base import Registry
from devforge.runtime.base import AgentRuntime

RuntimeFactory = Callable[[], AgentRuntime]


class RuntimeRegistry(Registry[RuntimeFactory]):
    def __init__(self) -> None:
        super().__init__("runtime")

    @classmethod
    def default(cls) -> RuntimeRegistry:
        from devforge.runtime.claude_code import ClaudeCodeRuntime
        from devforge.runtime.mock import MockAgentRuntime

        registry = cls()
        registry.register(MockAgentRuntime.name, MockAgentRuntime)
        registry.register(ClaudeCodeRuntime.name, ClaudeCodeRuntime)
        registry.register_profiles()
        return registry

    def register_profiles(self, project_root: object = None) -> list[str]:
        """Register every external CLI described by a runtime profile.

        Profiles are YAML (``builtin/runtimes/``, overridable from
        ``.devforge/runtimes/``), so a new provider is a file rather than a class.
        A profile whose id is already taken does not replace the built-in adapter:
        a hand-written adapter knows things a profile cannot express, and silently
        shadowing it would be a downgrade nobody asked for.
        """
        from devforge.runtime.external import runtime_factories

        added: list[str] = []
        for name, factory in runtime_factories(project_root).items():
            if name in self:
                continue
            self.register(name, factory)
            added.append(name)
        return added

    def create(self, name: str) -> AgentRuntime:
        return self.get(name)()

    def availability(self) -> dict[str, tuple[bool, str]]:
        """Name -> (available, detail) for every registered runtime."""
        report: dict[str, tuple[bool, str]] = {}
        for name in self.names():
            try:
                status = self.create(name).availability()
                report[name] = (status.available, status.detail or status.version)
            except Exception as exc:  # a broken adapter must not break `doctor`
                report[name] = (False, f"failed to construct: {exc}")
        return report

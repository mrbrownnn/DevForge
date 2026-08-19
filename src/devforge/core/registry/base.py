"""A small generic registry.

Skills, tools, agents and runtimes all need the same thing: name -> item, with
duplicate detection and a helpful error when a lookup misses. One implementation
serves all four; the orchestrator depends on the registry interface rather than
on any concrete catalogue, so new items are added without touching it.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Generic, TypeVar

from devforge.core.errors import RegistryError

T = TypeVar("T")


class Registry(Generic[T]):
    def __init__(self, kind: str) -> None:
        self.kind = kind
        self._items: dict[str, T] = {}

    def register(self, name: str, item: T, *, replace: bool = False) -> T:
        if not name:
            raise RegistryError(f"{self.kind} name must not be empty")
        if name in self._items and not replace:
            raise RegistryError(f"{self.kind} '{name}' is already registered")
        self._items[name] = item
        return item

    def unregister(self, name: str) -> None:
        self._items.pop(name, None)

    def get(self, name: str) -> T:
        try:
            return self._items[name]
        except KeyError:
            available = ", ".join(self.names()) or "<none>"
            raise RegistryError(f"unknown {self.kind} '{name}'. Available: {available}") from None

    def try_get(self, name: str) -> T | None:
        return self._items.get(name)

    def names(self) -> list[str]:
        return sorted(self._items)

    def all(self) -> list[T]:
        return [self._items[name] for name in self.names()]

    def items(self) -> dict[str, T]:
        return dict(self._items)

    def __contains__(self, name: object) -> bool:
        return name in self._items

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[T]:
        return iter(self.all())

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Registry({self.kind!r}, {len(self)} items)"

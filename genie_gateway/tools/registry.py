"""Tool registry and plain-text router. The caller can force a tool with `tool=` or a `slack:`-style prefix."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ..config import Settings
from .genie import GenieAdapter
from .jira import JiraAdapter
from .slack import SlackAdapter


class ToolAdapter(Protocol):
    name: str

    async def run(self, question: str, *, user: dict[str, Any], **options: Any) -> dict[str, Any]: ...


class UnknownTool(Exception):
    pass


@dataclass(frozen=True)
class Route:
    tool: str
    question: str


class ToolRegistry:
    def __init__(self, adapters: dict[str, ToolAdapter]) -> None:
        self._adapters = adapters

    @classmethod
    def from_settings(cls, settings: Settings) -> "ToolRegistry":
        return cls(
            {
                "genie": GenieAdapter(settings),
                "slack": SlackAdapter(settings),
                "jira": JiraAdapter(settings),
            }
        )

    @property
    def names(self) -> list[str]:
        return sorted(self._adapters)

    def get(self, name: str) -> ToolAdapter:
        if name not in self._adapters:
            raise UnknownTool(f"unknown tool '{name}'; available: {', '.join(self.names)}")
        return self._adapters[name]

    def route(self, question: str, tool: str | None = None) -> Route:
        """Pick the tool. Explicit `tool` wins, then `name:` prefix, then keywords, default Genie."""
        text = question.strip()
        lowered = text.lower()
        for prefix in ("genie:", "slack:", "jira:"):
            if lowered.startswith(prefix):
                return Route(self._checked(prefix[:-1]), text[len(prefix):].strip())
        if tool:
            return Route(self._checked(tool), text)
        if lowered.startswith("jql:"):
            return Route(self._checked("jira"), text)
        if "slack" in lowered and "slack" in self._adapters:
            return Route("slack", text)
        if ("jira" in lowered or "ticket" in lowered) and "jira" in self._adapters:
            return Route("jira", text)
        return Route(self._checked("genie"), text)

    def _checked(self, name: str) -> str:
        """Validate a tool key and return it. Keys, not adapter.name, are what grants refer to."""
        self.get(name)
        return name

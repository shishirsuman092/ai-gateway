"""Roles and tool privileges. Admins manage users and can use every tool."""

from __future__ import annotations

from typing import Any

ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLES = (ROLE_ADMIN, ROLE_USER)
KNOWN_TOOLS = ("genie", "slack", "jira")


class Forbidden(Exception):
    """Caller lacks the role or tool grant for the action."""


def can_use_tool(user: dict[str, Any], tool: str) -> bool:
    return user["role"] == ROLE_ADMIN or tool in user["tools"]


def require_tool(user: dict[str, Any], tool: str) -> None:
    if not can_use_tool(user, tool):
        raise Forbidden(f"user {user['email']} has no grant for tool '{tool}'")


def require_admin(user: dict[str, Any]) -> None:
    if user["role"] != ROLE_ADMIN:
        raise Forbidden("admin role required")

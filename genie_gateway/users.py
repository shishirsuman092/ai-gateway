"""User management: create, update, grant tools, seed the first admin."""

from __future__ import annotations

import json
import time
from typing import Any

from .db import Database
from .rbac import KNOWN_TOOLS, ROLES, ROLE_ADMIN, ROLE_USER


KINDS = ("human", "service")


class UserError(Exception):
    """Bad input or conflict in user management."""


class UserService:
    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _public(row: dict[str, Any] | None) -> dict[str, Any] | None:
        if row is None:
            return None
        row = dict(row)
        row["tools"] = json.loads(row["tools"] or "[]")
        row["is_active"] = bool(row["is_active"])
        row["must_change_password"] = bool(row["must_change_password"])
        row.pop("password_hash", None)
        return row

    def get(self, email: str) -> dict[str, Any] | None:
        return self._public(self.db.one("SELECT * FROM users WHERE email = ?", (email.lower(),)))

    def get_with_secret(self, email: str) -> dict[str, Any] | None:
        """Row including password_hash. Only the auth layer should call this."""
        row = self.db.one("SELECT * FROM users WHERE email = ?", (email.lower(),))
        return dict(row) if row else None

    def list(self) -> list[dict[str, Any]]:
        return [self._public(r) for r in self.db.many("SELECT * FROM users ORDER BY email")]

    @staticmethod
    def _check_tools(tools: list[str]) -> list[str]:
        unknown = [t for t in tools if t not in KNOWN_TOOLS]
        if unknown:
            raise UserError(f"unknown tool(s): {', '.join(unknown)}")
        return sorted(set(tools))

    def create(
        self,
        email: str,
        *,
        provider: str,
        name: str = "",
        role: str = ROLE_USER,
        tools: list[str] | None = None,
        password_hash: str | None = None,
        must_change_password: bool = False,
        kind: str = "human",
    ) -> dict[str, Any]:
        email = email.strip().lower()
        if kind not in KINDS:
            raise UserError(f"kind must be one of {KINDS}")
        # Humans need an email. Service accounts are keyed by Databricks applicationId (a UUID).
        if not email or (kind == "human" and "@" not in email):
            raise UserError("valid email required" if kind == "human" else "applicationId required")
        if kind == "service" and (password_hash or must_change_password):
            raise UserError("service accounts cannot have a password")
        if role not in ROLES:
            raise UserError(f"role must be one of {ROLES}")
        if self.get(email) is not None:
            raise UserError(f"user {email} already exists")
        self.db.execute(
            "INSERT INTO users (email, name, role, provider, password_hash, must_change_password, "
            "is_active, tools, kind, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
            (
                email,
                name,
                role,
                provider,
                password_hash,
                int(must_change_password),
                json.dumps(self._check_tools(tools or [])),
                kind,
                time.time(),
            ),
        )
        return self.get(email)  # type: ignore[return-value]

    def update(
        self,
        email: str,
        *,
        role: str | None = None,
        tools: list[str] | None = None,
        is_active: bool | None = None,
        name: str | None = None,
    ) -> dict[str, Any]:
        user = self.get(email)
        if user is None:
            raise UserError(f"user {email} not found")
        if role is not None:
            if role not in ROLES:
                raise UserError(f"role must be one of {ROLES}")
            if user["role"] == ROLE_ADMIN and role != ROLE_ADMIN and self.count_admins() <= 1:
                raise UserError("cannot demote the last admin")
            self.db.execute("UPDATE users SET role = ? WHERE email = ?", (role, user["email"]))
        if tools is not None:
            self.db.execute(
                "UPDATE users SET tools = ? WHERE email = ?",
                (json.dumps(self._check_tools(tools)), user["email"]),
            )
        if is_active is not None:
            if not is_active and user["role"] == ROLE_ADMIN and self.count_admins(active_only=True) <= 1:
                raise UserError("cannot disable the last active admin")
            self.db.execute(
                "UPDATE users SET is_active = ? WHERE email = ?", (int(is_active), user["email"])
            )
        if name is not None:
            self.db.execute("UPDATE users SET name = ? WHERE email = ?", (name, user["email"]))
        return self.get(user["email"])  # type: ignore[return-value]

    def record_login_failure(self, email: str, *, max_failures: int, lockout_seconds: int) -> bool:
        """Count a failed password attempt. Returns True when this failure starts a lockout."""
        now = time.time()
        row = self.db.one("SELECT failed_logins FROM users WHERE email = ?", (email.lower(),))
        if row is None:
            return False
        failures = int(row["failed_logins"]) + 1
        if failures >= max_failures:
            self.db.execute(
                "UPDATE users SET failed_logins = 0, locked_until = ? WHERE email = ?",
                (now + lockout_seconds, email.lower()),
            )
            return True
        self.db.execute("UPDATE users SET failed_logins = ? WHERE email = ?", (failures, email.lower()))
        return False

    def clear_login_failures(self, email: str) -> None:
        self.db.execute("UPDATE users SET failed_logins = 0, locked_until = 0 WHERE email = ?", (email.lower(),))

    def is_locked(self, email: str) -> bool:
        row = self.db.one("SELECT locked_until FROM users WHERE email = ?", (email.lower(),))
        return bool(row) and float(row["locked_until"]) > time.time()

    def set_password_hash(self, email: str, password_hash: str, *, must_change: bool) -> None:
        self.db.execute(
            "UPDATE users SET password_hash = ?, must_change_password = ? WHERE email = ?",
            (password_hash, int(must_change), email.lower()),
        )

    def provision_sso(self, email: str, name: str, provider: str) -> dict[str, Any]:
        """First SSO login creates a plain user with no tool grants. Admin grants more later."""
        existing = self.get(email)
        if existing is not None:
            return existing
        return self.create(email, provider=provider, name=name, role=ROLE_USER)

    def count_admins(self, active_only: bool = False) -> int:
        sql = "SELECT COUNT(*) AS n FROM users WHERE role = ?"
        if active_only:
            sql += " AND is_active = 1"
        return int(self.db.one(sql, (ROLE_ADMIN,))["n"])  # type: ignore[index]

    def seed_admin(self, email: str, *, provider: str, password_hash: str | None) -> None:
        """Create the demo admin on first boot. Idempotent: does nothing once an admin exists."""
        if self.count_admins() > 0:
            return
        existing = self.get_with_secret(email)
        if existing is not None:
            self.db.execute("UPDATE users SET role = ? WHERE email = ?", (ROLE_ADMIN, email.lower()))
            return
        self.create(
            email,
            provider=provider,
            name="Administrator",
            role=ROLE_ADMIN,
            password_hash=password_hash,
            must_change_password=password_hash is not None,
        )

"""Append-only audit trail for security-relevant events. There is no update or delete API."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from .db import Database

log = logging.getLogger("genie_gateway.audit")

OUTCOMES = ("success", "failure", "denied")


class AuditLog:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record(
        self,
        action: str,
        *,
        outcome: str,
        actor: str | None = None,
        target: str | None = None,
        detail: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        if outcome not in OUTCOMES:
            raise ValueError(f"outcome must be one of {OUTCOMES}")
        ts = time.time()
        payload = json.dumps(detail, default=str) if detail else None
        self.db.execute(
            "INSERT INTO audit_log (ts, request_id, actor, action, target, outcome, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, request_id, actor, action, target, outcome, payload),
        )
        # Mirror to the log stream so SIEM collectors see it even if the DB is lost.
        log.info(
            "audit action=%s outcome=%s actor=%s target=%s request_id=%s",
            action, outcome, actor, target, request_id,
        )

    def list(self, *, limit: int = 100, actor: str | None = None, action: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM audit_log WHERE 1=1"
        params: list[Any] = []
        if actor:
            sql += " AND actor = ?"
            params.append(actor)
        if action:
            sql += " AND action = ?"
            params.append(action)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        rows = self.db.many(sql, tuple(params))
        for row in rows:
            row["detail"] = json.loads(row["detail"]) if row["detail"] else None
        return rows

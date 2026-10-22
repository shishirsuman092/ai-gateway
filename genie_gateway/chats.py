"""Chat history: conversations and their messages. Stores what was sent (after redaction), never raw secrets."""

from __future__ import annotations

import time
import uuid
from typing import Any

from .db import Database


class ChatNotFound(Exception):
    pass


class ChatService:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, user: dict[str, Any], title: str) -> dict[str, Any]:
        now = time.time()
        chat_id = uuid.uuid4().hex
        self.db.execute(
            "INSERT INTO conversations (id, user_email, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (chat_id, user["email"], title[:80] or "Untitled", now, now),
        )
        return self.get(user, chat_id)

    def get(self, user: dict[str, Any], chat_id: str) -> dict[str, Any]:
        row = self.db.one("SELECT * FROM conversations WHERE id = ?", (chat_id,))
        if row is None or (row["user_email"] != user["email"] and user["role"] != "admin"):
            # Same answer for missing and not-yours, so ids cannot be probed.
            raise ChatNotFound(f"no conversation {chat_id}")
        return row

    def list_for(self, user: dict[str, Any], limit: int = 20) -> list[dict[str, Any]]:
        return self.db.many(
            "SELECT id, title, created_at, updated_at FROM conversations WHERE user_email = ? "
            "ORDER BY updated_at DESC LIMIT ?",
            (user["email"], max(1, min(limit, 100))),
        )

    def messages(self, user: dict[str, Any], chat_id: str) -> dict[str, Any]:
        conv = self.get(user, chat_id)
        rows = self.db.many(
            "SELECT role, content, job_id, created_at FROM messages WHERE conversation_id = ? ORDER BY id",
            (chat_id,),
        )
        return {"conversation_id": chat_id, "title": conv["title"], "messages": rows}

    def add_message(self, chat_id: str, role: str, content: str, job_id: str | None = None) -> None:
        now = time.time()
        self.db.execute(
            "INSERT INTO messages (conversation_id, role, content, job_id, created_at) VALUES (?, ?, ?, ?, ?)",
            (chat_id, role, content, job_id, now),
        )
        self.db.execute("UPDATE conversations SET updated_at = ? WHERE id = ?", (now, chat_id))

    def genie_conversation(self, chat_id: str) -> str | None:
        row = self.db.one("SELECT genie_conversation_id FROM conversations WHERE id = ?", (chat_id,))
        return row["genie_conversation_id"] if row else None

    def set_genie_conversation(self, chat_id: str, genie_conversation_id: str) -> None:
        self.db.execute(
            "UPDATE conversations SET genie_conversation_id = ? WHERE id = ?", (genie_conversation_id, chat_id)
        )

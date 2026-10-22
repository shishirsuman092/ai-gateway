"""Async query jobs. submit() returns at once; a background task calls the tool and stores the result.

Callers poll get() or long-poll wait(). Jobs live in SQLite, so results survive a restart.
Jobs that were running when the process died are marked FAILED on startup (no silent retry).

Secrets held for a job are short-lived: a caller's PAT (user_pat mode) is stored encrypted and
erased as soon as the job reads it; chat context is erased once it has been summarized.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any

from . import guardrails
from .audit import AuditLog
from .chats import ChatNotFound, ChatService
from .databricks_auth import CredentialError, decrypt_token, encrypt_token
from .db import Database
from .guardrails import MAX_QUESTION_CHARS
from .rbac import ROLE_ADMIN, Forbidden, require_tool
from .summarizer import Summarizer
from .tools import ToolRegistry, UnknownTool

log = logging.getLogger("genie_gateway.jobs")

QUEUED, RUNNING, COMPLETED, FAILED = "QUEUED", "RUNNING", "COMPLETED", "FAILED"
TERMINAL = {COMPLETED, FAILED}
MAX_WAIT_SECONDS = 60
MAX_CONTEXT_CHARS = 200_000  # hard cap on chat context accepted in one request


class JobError(Exception):
    pass


class JobNotFound(JobError):
    pass


class JobService:
    def __init__(
        self,
        db: Database,
        registry: ToolRegistry,
        *,
        audit: AuditLog | None = None,
        guardrails_enabled: bool = True,
        max_question_chars: int = MAX_QUESTION_CHARS,
        chats: ChatService | None = None,
        summarizer: Summarizer | None = None,
        auth_mode: str = "service_principal",
        encryption_key: str = "",
    ) -> None:
        self.db = db
        self.registry = registry
        self.audit = audit
        self.guardrails_enabled = guardrails_enabled
        self.max_question_chars = max_question_chars
        self.chats = chats
        self.summarizer = summarizer
        self.auth_mode = auth_mode
        self.encryption_key = encryption_key
        self._tasks: set[asyncio.Task] = set()

    def recover(self) -> int:
        """Mark jobs left QUEUED/RUNNING by a previous process as FAILED and erase their secrets."""
        now = time.time()
        stale = self.db.many("SELECT id FROM jobs WHERE status IN (?, ?)", (QUEUED, RUNNING))
        for row in stale:
            self._finish(row["id"], FAILED, error="gateway restarted before the job finished", now=now)
            self.db.execute("UPDATE jobs SET user_token_enc = NULL, context_raw = NULL WHERE id = ?", (row["id"],))
        return len(stale)

    def submit(
        self,
        user: dict[str, Any],
        question: str,
        tool: str | None = None,
        *,
        conversation_id: str | None = None,
        chat_context: str | None = None,
        context_summary: str | None = None,
        user_token: str | None = None,
    ) -> dict[str, Any]:
        question = (question or "").strip()
        if not question:
            raise JobError("question is empty")
        redactions: list[str] = []
        if self.guardrails_enabled:
            try:
                verdict = guardrails.check_input(question, max_chars=self.max_question_chars)
            except guardrails.GuardrailBlock as exc:
                self._audit("query.blocked", "denied", user, detail={"reason": str(exc)})
                raise JobError(f"blocked by guardrail: {exc}") from exc
            question, redactions = verdict.question, verdict.redactions
        try:
            route = self.registry.route(question, tool)
        except UnknownTool as exc:
            raise JobError(str(exc)) from exc
        try:
            require_tool(user, route.tool)
        except Forbidden:
            self._audit("query.denied", "denied", user, detail={"tool": route.tool})
            raise
        if route.tool == "genie" and self.auth_mode == "user_pat" and not user_token:
            raise JobError("DATABRICKS_AUTH_MODE=user_pat: sign in with a Databricks PAT to query Genie")
        if chat_context and len(chat_context) > MAX_CONTEXT_CHARS:
            raise JobError(f"chat_context is longer than {MAX_CONTEXT_CHARS} characters")
        if redactions:
            self._audit("query.redacted", "success", user, detail={"kinds": redactions})

        chat_id = self._chat_for(user, conversation_id, route.question)

        job_id = uuid.uuid4().hex
        now = time.time()
        context = None
        if context_summary:
            context = {"kind": "summary", "text": guardrails.redact(context_summary)[0]}
        elif chat_context:
            context = {"kind": "raw", "text": guardrails.redact(chat_context)[0]}
        token_enc = encrypt_token(self.encryption_key, user_token) if user_token and self.encryption_key else None
        self.db.execute(
            "INSERT INTO jobs (id, user_email, tool, question, status, created_at, updated_at, "
            "conversation_id, user_token_enc, context_raw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (job_id, user["email"], route.tool, route.question, QUEUED, now, now, chat_id, token_enc,
             json.dumps(context) if context else None),
        )
        if chat_id:
            self.chats.add_message(chat_id, "user", route.question, job_id)
            if context and context["kind"] == "summary":
                self.chats.add_message(chat_id, "summary", context["text"], job_id)

        task = asyncio.create_task(self._run(job_id, route.tool, route.question, user, chat_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        self._audit("query.submit", "success", user, target=job_id,
                    detail={"tool": route.tool, "conversation_id": chat_id, "context": bool(context)})
        return self.public(self._load(job_id))

    def _chat_for(self, user: dict[str, Any], conversation_id: str | None, question: str) -> str | None:
        if self.chats is None:
            return None
        if conversation_id:
            try:
                return self.chats.get(user, conversation_id)["id"]
            except ChatNotFound as exc:
                raise JobError(str(exc)) from exc
        return self.chats.create(user, question)["id"]

    async def _run(self, job_id: str, tool: str, question: str, user: dict[str, Any], chat_id: str | None) -> None:
        self._set_status(job_id, RUNNING)
        try:
            token = self._take_secret(job_id)
            prompt = await self._with_context(job_id, question, chat_id)
            options: dict[str, Any] = {"user_token": token}
            if chat_id and tool == "genie":
                options["genie_conversation_id"] = self.chats.genie_conversation(chat_id)
            result = await self.registry.get(tool).run(prompt, user=user, **options)
        except asyncio.CancelledError:
            self._finish(job_id, FAILED, error="cancelled")
            raise
        except Exception as exc:  # any failure becomes a job result, not a crash
            log.warning("job %s (%s) failed: %s", job_id, tool, exc)
            self._finish(job_id, FAILED, error=f"{type(exc).__name__}: {exc}")
            return
        finally:
            self.db.execute("UPDATE jobs SET user_token_enc = NULL WHERE id = ?", (job_id,))

        if self.guardrails_enabled and isinstance(result, dict):
            result, applied = guardrails.check_output(result)
            if applied:
                result["guardrails"] = applied
                self._audit("result.redacted", "success", user, target=job_id, detail={"kinds": applied})
        if chat_id:
            if tool == "genie" and result.get("conversation_id"):
                self.chats.set_genie_conversation(chat_id, result["conversation_id"])
            self.chats.add_message(chat_id, "assistant", result.get("answer") or json.dumps(result), job_id)
        self._finish(job_id, COMPLETED, result=result)

    def _take_secret(self, job_id: str) -> str | None:
        """Read and erase the caller's PAT in one step. Returns None if the job has none."""
        row = self.db.one("SELECT user_token_enc FROM jobs WHERE id = ?", (job_id,))
        if not row or not row["user_token_enc"]:
            return None
        self.db.execute("UPDATE jobs SET user_token_enc = NULL WHERE id = ?", (job_id,))
        try:
            return decrypt_token(self.encryption_key, row["user_token_enc"])
        except CredentialError as exc:
            raise JobError(str(exc)) from exc

    async def _with_context(self, job_id: str, question: str, chat_id: str | None) -> str:
        """Build the prompt: summarized chat context (if any) followed by the question. Erases raw context."""
        row = self.db.one("SELECT context_raw FROM jobs WHERE id = ?", (job_id,))
        self.db.execute("UPDATE jobs SET context_raw = NULL WHERE id = ?", (job_id,))
        if not row or not row["context_raw"]:
            return question
        context = json.loads(row["context_raw"])
        if context["kind"] == "summary":
            summary = context["text"]
        else:
            if self.summarizer is None:
                raise JobError("chat_context needs a summarizer; set SUMMARIZER_PROVIDER or pass context_summary")
            summary = await self.summarizer.summarize(context["text"])
            if chat_id:
                self.chats.add_message(chat_id, "summary", summary, job_id)
        return f"Conversation context:\n{summary}\n\nQuestion: {question}"

    def _audit(self, action: str, outcome: str, user: dict[str, Any], *, target: str | None = None,
               detail: dict[str, Any] | None = None) -> None:
        if self.audit is not None:
            self.audit.record(action, outcome=outcome, actor=user.get("email"), target=target, detail=detail)

    def get(self, user: dict[str, Any], job_id: str) -> dict[str, Any]:
        row = self._load(job_id)
        if row is None or (row["user_email"] != user["email"] and user["role"] != ROLE_ADMIN):
            # Same answer for "missing" and "not yours", so job ids cannot be probed.
            raise JobNotFound(f"no job {job_id}")
        return self.public(row)

    async def wait(self, user: dict[str, Any], job_id: str, timeout: float) -> dict[str, Any]:
        """Long-poll: return as soon as the job is terminal, or after `timeout` seconds."""
        deadline = time.monotonic() + min(max(timeout, 0), MAX_WAIT_SECONDS)
        while True:
            job = self.get(user, job_id)
            if job["status"] in TERMINAL or time.monotonic() >= deadline:
                return job
            await asyncio.sleep(0.25)

    def list_for(self, user: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
        rows = self.db.many(
            "SELECT * FROM jobs WHERE user_email = ? ORDER BY created_at DESC LIMIT ?",
            (user["email"], max(1, min(limit, 100))),
        )
        return [self.public(r) for r in rows]

    async def drain(self) -> None:
        """Wait for in-flight jobs (used by tests and clean shutdown)."""
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    # storage helpers

    def _load(self, job_id: str) -> dict[str, Any] | None:
        return self.db.one("SELECT * FROM jobs WHERE id = ?", (job_id,))

    def _set_status(self, job_id: str, status: str) -> None:
        self.db.execute("UPDATE jobs SET status = ?, updated_at = ? WHERE id = ?", (status, time.time(), job_id))

    def _finish(
        self,
        job_id: str,
        status: str,
        *,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        now: float | None = None,
    ) -> None:
        self.db.execute(
            "UPDATE jobs SET status = ?, result = ?, error = ?, updated_at = ? WHERE id = ?",
            (status, json.dumps(result) if result is not None else None, error, now or time.time(), job_id),
        )

    @staticmethod
    def public(row: dict[str, Any] | None) -> dict[str, Any] | None:
        if row is None:
            return None
        return {
            "job_id": row["id"],
            "tool": row["tool"],
            "question": row["question"],
            "status": row["status"],
            "conversation_id": row.get("conversation_id"),
            "result": json.loads(row["result"]) if row["result"] else None,
            "error": row["error"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

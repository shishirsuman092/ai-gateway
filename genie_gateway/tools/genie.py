"""Databricks Genie adapter (Conversation API, workspace scoped; Unity Catalog governs the data).

Genie answers asynchronously: start (or continue) a conversation, then poll the message until it
reaches a terminal status. Who Genie runs as depends on DATABRICKS_AUTH_MODE:
  - service_principal: the gateway identity (OAuth M2M or static PAT).
  - user_pat: the caller's own PAT, passed per job as options["user_token"].
Mock mode (Genie not configured) returns a canned answer after a short delay.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

import logging

import httpx

from ..config import Settings
from ..databricks_auth import ServicePrincipalAuth

log = logging.getLogger("genie_gateway.genie")
TERMINAL_STATUSES = {"COMPLETED", "FAILED", "CANCELLED", "QUERY_RESULT_EXPIRED"}


class GenieError(Exception):
    pass


class GenieAdapter:
    name = "genie"

    def __init__(
        self,
        settings: Settings,
        http: httpx.AsyncClient | None = None,
        credentials: ServicePrincipalAuth | None = None,
    ) -> None:
        self.live = settings.genie_live
        self.mode = settings.databricks_auth_mode
        self.space_id = settings.genie_space_id
        self.poll_seconds = settings.genie_poll_seconds
        self.timeout_seconds = settings.job_timeout_seconds
        host = settings.databricks_host.rstrip("/")
        if self.live and http is None:
            http = httpx.AsyncClient(base_url=host, timeout=30)
        self._http = http
        if self.live and self.mode == "service_principal" and credentials is None:
            credentials = ServicePrincipalAuth(
                host,
                static_token=settings.databricks_token,
                client_id=settings.databricks_client_id,
                client_secret=settings.databricks_client_secret,
            )
        self._credentials = credentials

    async def run(self, question: str, *, user: dict[str, Any], **options: Any) -> dict[str, Any]:
        follow_up = options.get("genie_conversation_id")
        if not self.live:
            await asyncio.sleep(min(self.poll_seconds, 1.0))
            return {
                "mode": "mock",
                "answer": f"[mock Genie] Answer to: {question}",
                "sql": None,
                "conversation_id": follow_up or f"mock-{uuid.uuid4().hex[:8]}",
            }

        headers = await self._auth_headers(options)
        log.info("genie run mode=%s auth=%s follow_up=%s space=%s", self.mode,
                 "caller_pat" if self.mode == "user_pat" else self._credentials.method,
                 bool(follow_up), self.space_id)
        if follow_up:
            conversation_id, message_id = await self._continue(follow_up, question, headers)
        else:
            conversation_id, message_id = await self._start(question, headers)

        deadline = time.monotonic() + self.timeout_seconds
        while True:
            message = await self._get_message(conversation_id, message_id, headers)
            status = message.get("status", "")
            if status in TERMINAL_STATUSES:
                break
            if time.monotonic() > deadline:
                raise GenieError(f"Genie did not finish within {self.timeout_seconds}s (last status {status})")
            await asyncio.sleep(self.poll_seconds)

        if status != "COMPLETED":
            detail = (message.get("error") or {}).get("message", "")
            raise GenieError(f"Genie status {status}: {detail}".rstrip(": "))
        return _summarise(message, conversation_id, message_id)

    async def _auth_headers(self, options: dict[str, Any]) -> dict[str, str]:
        if self.mode == "user_pat":
            token = options.get("user_token")
            if not token:
                raise GenieError("user_pat mode: the caller must present a Databricks PAT")
            return {"Authorization": f"Bearer {token}"}
        return {"Authorization": await self._credentials.authorization()}

    async def _start(self, question: str, headers: dict[str, str]) -> tuple[str, str]:
        resp = await self._http.post(
            f"/api/2.0/genie/spaces/{self.space_id}/start-conversation",
            json={"content": question},
            headers=headers,
        )
        _check(resp, "start-conversation")
        body = resp.json()
        return body["conversation_id"], body["message_id"]

    async def _continue(self, conversation_id: str, question: str, headers: dict[str, str]) -> tuple[str, str]:
        resp = await self._http.post(
            f"/api/2.0/genie/spaces/{self.space_id}/conversations/{conversation_id}/messages",
            json={"content": question},
            headers=headers,
        )
        _check(resp, "continue-conversation")
        return conversation_id, resp.json()["message_id"]

    async def _get_message(self, conversation_id: str, message_id: str, headers: dict[str, str]) -> dict[str, Any]:
        resp = await self._http.get(
            f"/api/2.0/genie/spaces/{self.space_id}/conversations/{conversation_id}/messages/{message_id}",
            headers=headers,
        )
        _check(resp, "get-message")
        return resp.json()


def _check(resp: httpx.Response, action: str) -> None:
    """Raise on HTTP error, logging the Databricks error body (never the Authorization header)."""
    if resp.status_code >= 400:
        log.error("genie %s failed status=%s body=%s", action, resp.status_code, resp.text[:400])
        resp.raise_for_status()


def _summarise(message: dict[str, Any], conversation_id: str, message_id: str) -> dict[str, Any]:
    texts: list[str] = []
    sql: str | None = None
    for attachment in message.get("attachments") or []:
        if "text" in attachment:
            texts.append(attachment["text"].get("content", ""))
        if "query" in attachment and sql is None:
            sql = attachment["query"].get("query")
    return {
        "mode": "live",
        "answer": "\n".join(t for t in texts if t).strip(),
        "sql": sql,
        "conversation_id": conversation_id,
        "message_id": message_id,
    }

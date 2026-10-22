"""Jira Cloud adapter. Plain text becomes `text ~ "..."`; `jql: ...` is passed through as JQL."""

from __future__ import annotations

from typing import Any

import httpx

from ..config import Settings
from .slack import ToolError


def to_jql(question: str) -> str:
    if question.lower().startswith("jql:"):
        return question[4:].strip()
    escaped = question.replace("\\", "\\\\").replace('"', '\\"')
    return f'text ~ "{escaped}" ORDER BY updated DESC'


class JiraAdapter:
    name = "jira"

    def __init__(self, settings: Settings, http: httpx.AsyncClient | None = None) -> None:
        self.live = settings.jira_live
        self._auth = (settings.jira_email, settings.jira_api_token)
        self._base = settings.jira_base_url.rstrip("/")
        if http is None and self.live:
            http = httpx.AsyncClient(timeout=30, headers={"Accept": "application/json"})
        self._http = http

    async def run(self, question: str, *, user: dict[str, Any], **options: Any) -> dict[str, Any]:
        jql = to_jql(question)
        if not self.live:
            return {
                "mode": "mock",
                "jql": jql,
                "issues": [{"key": "DEMO-1", "summary": f"[mock Jira] {question}", "status": "To Do"}],
            }
        resp = await self._http.post(
            f"{self._base}/rest/api/3/search/jql",
            json={"jql": jql, "maxResults": 5, "fields": ["summary", "status"]},
            auth=self._auth,
        )
        if resp.status_code >= 400:
            raise ToolError(f"Jira HTTP {resp.status_code}: {resp.text[:200]}")
        issues = resp.json().get("issues", [])
        return {
            "mode": "live",
            "jql": jql,
            "issues": [
                {
                    "key": i["key"],
                    "summary": i["fields"]["summary"],
                    "status": i["fields"]["status"]["name"],
                }
                for i in issues
            ],
        }

"""Slack adapter: searches messages the token's user can see (search.messages needs a user token)."""

from __future__ import annotations

from typing import Any

import httpx

from ..config import Settings

SEARCH_URL = "https://slack.com/api/search.messages"


class ToolError(Exception):
    pass


class SlackAdapter:
    name = "slack"

    def __init__(self, settings: Settings, http: httpx.AsyncClient | None = None) -> None:
        self.live = settings.slack_live
        if http is None and self.live:
            http = httpx.AsyncClient(
                headers={"Authorization": f"Bearer {settings.slack_user_token}"}, timeout=30
            )
        self._http = http

    async def run(self, question: str, *, user: dict[str, Any], **options: Any) -> dict[str, Any]:
        if not self.live:
            return {
                "mode": "mock",
                "matches": [
                    {"text": f"[mock Slack] message matching: {question}", "channel": "general", "permalink": None}
                ],
            }
        resp = await self._http.get(SEARCH_URL, params={"query": question, "count": 5})
        resp.raise_for_status()
        data = resp.json()
        if not data.get("ok"):
            raise ToolError(f"Slack error: {data.get('error', 'unknown')}")
        matches = data.get("messages", {}).get("matches", [])
        return {
            "mode": "live",
            "matches": [
                {
                    "text": m.get("text", ""),
                    "channel": (m.get("channel") or {}).get("name"),
                    "permalink": m.get("permalink"),
                }
                for m in matches
            ],
        }

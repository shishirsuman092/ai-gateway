"""Summarize chat context before it is sent to Genie.

Providers: none (keep the most recent SUMMARIZER_MAX_CHARS characters), openai, anthropic.
If a provider call fails, the gateway falls back to truncation and logs a warning, so a
query is never lost because the summarizer is down. Summaries pass through redaction.
"""

from __future__ import annotations

import logging

import httpx

from .config import Settings
from .guardrails import redact

log = logging.getLogger("genie_gateway.summarizer")

SYSTEM_PROMPT = (
    "Summarize this chat for a data-analytics assistant that will answer a new question. "
    "Keep entities, metrics, filters, time ranges, and any conclusions already reached. "
    "Drop greetings and filler. Plain text, at most 200 words."
)


def truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return "[earlier context truncated]\n" + text[-max_chars:]


class Summarizer:
    def __init__(self, settings: Settings, http: httpx.AsyncClient | None = None) -> None:
        self.provider = settings.summarizer_provider
        self.api_key = settings.summarizer_api_key
        self.model = settings.summarizer_model
        self.max_chars = settings.summarizer_max_chars
        self._http = http or httpx.AsyncClient(timeout=60)

    async def summarize(self, text: str) -> str:
        source = truncate(text, self.max_chars)
        if self.provider == "none":
            return redact(source)[0]
        try:
            if self.provider == "openai":
                summary = await self._openai(source)
            else:
                summary = await self._anthropic(source)
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            log.warning("summarizer %s failed, using truncated context: %s", self.provider, exc)
            return redact(source)[0]
        return redact(summary)[0]

    async def _openai(self, text: str) -> str:
        resp = await self._http.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": text},
                ],
            },
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()

    async def _anthropic(self, text: str) -> str:
        resp = await self._http.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
            json={
                "model": self.model,
                "max_tokens": 600,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": text}],
            },
        )
        resp.raise_for_status()
        parts = [b["text"] for b in resp.json()["content"] if b.get("type") == "text"]
        return "\n".join(parts).strip()

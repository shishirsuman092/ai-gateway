"""Credentials for calling Databricks on the gateway's behalf, and encryption for caller PATs.

service_principal mode: the gateway calls Genie as one identity.
  - OAuth M2M (DATABRICKS_CLIENT_ID + DATABRICKS_CLIENT_SECRET): short-lived tokens, refreshed automatically.
  - Static PAT (DATABRICKS_TOKEN): used as-is, for demos and legacy setups.
user_pat mode: each query runs as the caller's own PAT. The PAT is encrypted (Fernet) while the job
  is queued and deleted as soon as the job has used it.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable

import httpx
from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger("genie_gateway.databricks")

REFRESH_MARGIN_SECONDS = 60


class CredentialError(Exception):
    pass


class ServicePrincipalAuth:
    """Returns an Authorization header value for the gateway identity."""

    def __init__(
        self,
        host: str,
        *,
        static_token: str = "",
        client_id: str = "",
        client_secret: str = "",
        http: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._host = host.rstrip("/")
        self._static = static_token
        self._client_id = client_id
        self._client_secret = client_secret
        self._http = http or httpx.AsyncClient(timeout=15)
        self._clock = clock
        self._token = ""
        self._expires_at = 0.0
        self._lock = asyncio.Lock()

    @property
    def method(self) -> str:
        return "static_token" if self._static else "oauth_m2m"

    async def authorization(self) -> str:
        if self._static:
            return f"Bearer {self._static}"
        async with self._lock:
            if not self._token or self._clock() >= self._expires_at - REFRESH_MARGIN_SECONDS:
                await self._refresh()
            return f"Bearer {self._token}"

    async def _refresh(self) -> None:
        log.info("oauth m2m token request host=%s client_id=%s", self._host, self._client_id[:8])
        try:
            resp = await self._http.post(
                f"{self._host}/oidc/v1/token",
                data={"grant_type": "client_credentials", "scope": "all-apis"},
                auth=(self._client_id, self._client_secret),
            )
        except httpx.HTTPError as exc:
            log.error("oauth m2m token unreachable host=%s error=%s", self._host, exc.__class__.__name__)
            raise CredentialError(f"Databricks token endpoint unreachable: {exc.__class__.__name__}") from exc
        if resp.status_code >= 400:
            log.error("oauth m2m token rejected host=%s status=%s body=%s", self._host, resp.status_code,
                      resp.text[:300])
            raise CredentialError(f"Databricks rejected the service principal credentials: HTTP {resp.status_code}")
        log.info("oauth m2m token ok expires_in=%s", resp.json().get("expires_in"))
        body = resp.json()
        self._token = body["access_token"]
        self._expires_at = self._clock() + float(body.get("expires_in", 3600))


def encrypt_token(key: str, token: str) -> str:
    return Fernet(key.encode()).encrypt(token.encode()).decode()


def decrypt_token(key: str, ciphertext: str) -> str:
    try:
        return Fernet(key.encode()).decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise CredentialError("stored credential cannot be decrypted; check GATEWAY_ENCRYPTION_KEY") from exc

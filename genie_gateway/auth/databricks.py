"""Databricks PAT provider. A PAT (prefix `dapi`) is checked against the workspace SCIM `Me` endpoint.

The workspace answers with the identity that owns the token: a user (SCIM User, userName = email)
or a service principal (SCIM ServicePrincipal, identified by applicationId). The gateway then maps
that identity to a gateway account. PATs are never stored; only a SHA-256 of a verified token is
cached, for DATABRICKS_PAT_CACHE_SECONDS, so revoked tokens stop working after at most that long.
"""

from __future__ import annotations

import hashlib
import time
from typing import Callable

import httpx

from .base import AuthError, Principal

PAT_PREFIX = "dapi"
ME_PATH = "/api/2.0/preview/scim/v2/Me"
SERVICE_PRINCIPAL_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServicePrincipal"
MAX_CACHE_ENTRIES = 1000


def looks_like_pat(token: str) -> bool:
    return token.startswith(PAT_PREFIX)


def principal_from_me(body: dict) -> Principal:
    if body.get("active") is False:
        raise AuthError("Databricks account is inactive")
    if SERVICE_PRINCIPAL_SCHEMA in body.get("schemas", []):
        app_id = body.get("applicationId") or body.get("userName")
        if not app_id:
            raise AuthError("Databricks service principal has no applicationId")
        return Principal(
            email=app_id.lower(),
            name=body.get("displayName", ""),
            provider="databricks",
            kind="service",
        )
    email = body.get("userName") or next((e.get("value") for e in body.get("emails", []) if e.get("primary")), None)
    if not email:
        raise AuthError("Databricks identity has no email")
    return Principal(email=email.lower(), name=body.get("displayName", ""), provider="databricks", kind="human")


class DatabricksPATVerifier:
    provider = "databricks"

    def __init__(
        self,
        host: str,
        *,
        cache_seconds: int = 300,
        http: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._me_url = host.rstrip("/") + ME_PATH
        self._cache_seconds = cache_seconds
        self._http = http or httpx.AsyncClient(timeout=10)
        self._clock = clock
        self._cache: dict[str, tuple[float, Principal]] = {}

    async def verify(self, token: str) -> Principal:
        key = hashlib.sha256(token.encode()).hexdigest()
        now = self._clock()
        cached = self._cache.get(key)
        if cached is not None and cached[0] > now:
            return cached[1]

        try:
            resp = await self._http.get(self._me_url, headers={"Authorization": f"Bearer {token}"})
        except httpx.HTTPError as exc:
            raise AuthError(f"Databricks unreachable: {exc.__class__.__name__}") from exc
        if resp.status_code in (401, 403):
            self._cache.pop(key, None)
            raise AuthError("Databricks rejected the PAT")
        if resp.status_code >= 400:
            raise AuthError(f"Databricks identity check failed: HTTP {resp.status_code}")

        principal = principal_from_me(resp.json())
        self._remember(key, principal, now)
        return principal

    def _remember(self, key: str, principal: Principal, now: float) -> None:
        if len(self._cache) >= MAX_CACHE_ENTRIES:
            self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
        self._cache[key] = (now + self._cache_seconds, principal)

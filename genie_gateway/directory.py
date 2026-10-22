"""Fetch the Databricks user and service-principal directory via SCIM, paged.

Source:
  - DATABRICKS_ACCOUNT_ID set: account-level SCIM (all workspaces in the account).
  - otherwise: this workspace's SCIM.
Needs a credential with directory read rights (workspace admin, or account admin for account-level).
Reads only; the caller decides what to import (see AuthService / admin sync endpoint).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

import httpx

import logging

from .config import Settings
from .databricks_auth import ServicePrincipalAuth
from .auth.databricks import SERVICE_PRINCIPAL_SCHEMA

log = logging.getLogger("genie_gateway.directory")
PAGE_SIZE = 100
MAX_PAGES = 1000  # guard against a server that never stops paging


class DirectoryError(Exception):
    pass


@dataclass(frozen=True)
class DirectoryEntry:
    email: str  # users: email; service principals: applicationId
    name: str
    kind: str  # human | service
    active: bool


class DatabricksDirectory:
    def __init__(
        self,
        settings: Settings,
        credentials: ServicePrincipalAuth,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self._credentials = credentials
        self._http = http or httpx.AsyncClient(timeout=30)
        if settings.databricks_account_id:
            base = f"{settings.databricks_account_host.rstrip('/')}/api/2.0/accounts/{settings.databricks_account_id}"
            self.scope = f"account:{settings.databricks_account_id}"
        else:
            base = settings.databricks_host.rstrip("/") + "/api/2.0/preview"
            self.scope = "workspace"
        self._base = base

    async def list_users(self) -> list[DirectoryEntry]:
        return await self._list("scim/v2/Users")

    async def list_service_principals(self) -> list[DirectoryEntry]:
        return await self._list("scim/v2/ServicePrincipals")

    async def list_all(self, *, include_service_principals: bool = True) -> list[DirectoryEntry]:
        entries = await self.list_users()
        if include_service_principals:
            entries += await self.list_service_principals()
        return entries

    async def _list(self, path: str) -> list[DirectoryEntry]:
        entries: list[DirectoryEntry] = []
        start = 1
        for _ in range(MAX_PAGES):
            resources, total = await self._page(path, start)
            for resource in resources:
                entries.append(_entry(resource))
            if not resources or start + len(resources) > total:
                break
            start += len(resources)
        return entries

    async def _page(self, path: str, start_index: int) -> tuple[list[dict[str, Any]], int]:
        try:
            resp = await self._http.get(
                f"{self._base}/{path}",
                params={"startIndex": start_index, "count": PAGE_SIZE},
                headers={"Authorization": await self._credentials.authorization()},
            )
        except httpx.HTTPError as exc:
            raise DirectoryError(f"Databricks unreachable: {exc.__class__.__name__}") from exc
        if resp.status_code >= 400:
            log.error("directory %s failed status=%s body=%s", path, resp.status_code, resp.text[:300])
        if resp.status_code in (401, 403):
            raise DirectoryError(f"Databricks denied directory access (HTTP {resp.status_code}); "
                                 "the credential needs directory read rights")
        if resp.status_code >= 400:
            raise DirectoryError(f"directory request failed: HTTP {resp.status_code}")
        body = resp.json()
        return body.get("Resources", []), int(body.get("totalResults", 0))


def _entry(resource: dict[str, Any]) -> DirectoryEntry:
    """Same identity keys as PAT checks, but inactive accounts are kept so the caller can report them."""
    if SERVICE_PRINCIPAL_SCHEMA in resource.get("schemas", []):
        key = resource.get("applicationId") or resource.get("userName") or ""
        kind = "service"
    else:
        key = resource.get("userName") or next(
            (e.get("value") for e in resource.get("emails", []) if e.get("primary")), ""
        )
        kind = "human"
    return DirectoryEntry(
        email=key.lower(),
        name=resource.get("displayName", ""),
        kind=kind,
        active=resource.get("active", True) is not False,
    )

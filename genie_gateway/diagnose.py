"""Startup summary and on-demand diagnosis. Never prints secrets: only lengths, prefixes and status codes."""

from __future__ import annotations

import logging
import time

import httpx

from .config import Settings
from .db import Database

log = logging.getLogger("genie_gateway.config")


def config_summary(settings: Settings) -> dict[str, object]:
    return {
        "app_env": settings.app_env,
        "public_base_url": settings.base_url,
        "https": settings.base_url.startswith("https://"),
        "auth_provider": settings.auth_provider,
        "oauth_enabled": settings.oauth_enabled,
        "databricks_host": settings.databricks_host or None,
        "databricks_auth_mode": settings.databricks_auth_mode,
        "databricks_credentials": _credential_kind(settings),
        "genie_space_id": settings.genie_space_id or None,
        "genie_live": settings.genie_live,
        "pat_auth_enabled": settings.pat_auth_enabled,
        "directory_scope": f"account:{settings.databricks_account_id}" if settings.databricks_account_id else "workspace",
        "summarizer": settings.summarizer_provider,
        "guardrails": settings.guardrails_enabled,
    }


def _credential_kind(settings: Settings) -> str:
    if settings.databricks_token:
        return "static_token(DATABRICKS_TOKEN)"
    if settings.databricks_client_id and settings.databricks_client_secret:
        return f"oauth_m2m(client_id={settings.databricks_client_id[:8]}...)"
    return "none"


def log_startup(settings: Settings) -> None:
    log.info("startup config %s", config_summary(settings))


def run_diagnose(settings: Settings) -> int:
    """Print a checklist. Exit code 0 when everything needed for the configured mode works."""
    ok = True

    def line(status: str, name: str, detail: str = "") -> None:
        print(f"[{status}] {name}{(': ' + detail) if detail else ''}")

    print("== config")
    for key, value in config_summary(settings).items():
        print(f"    {key} = {value}")

    print("== local accounts (gateway database)")
    try:
        db = Database(settings.db_path)
        rows = db.many("SELECT email, kind, role, provider, is_active, must_change_password, "
                       "failed_logins, locked_until FROM users ORDER BY email")
        for r in rows:
            locked = max(0.0, float(r["locked_until"]) - time.time())
            flags = []
            if not r["is_active"]:
                flags.append("DISABLED")
            if r["must_change_password"]:
                flags.append("must-change-password")
            if locked:
                flags.append(f"LOCKED {locked:.0f}s")
            if r["failed_logins"]:
                flags.append(f"failed_logins={r['failed_logins']}")
            print(f"    {r['email']} kind={r['kind']} role={r['role']} provider={r['provider']} "
                  f"{' '.join(flags)}".rstrip())
        line("OK", "database readable", f"{len(rows)} accounts")
    except Exception as exc:  # report, do not crash the checklist
        ok = False
        line("FAIL", "database", f"{type(exc).__name__}: {exc}")

    if not settings.databricks_host:
        line("SKIP", "databricks", "DATABRICKS_HOST not set (mock mode)")
        return 0 if ok else 1

    print("== databricks")
    with httpx.Client(timeout=20) as http:
        host = settings.databricks_host.rstrip("/")
        token = settings.databricks_token
        if not token and settings.databricks_client_id and settings.databricks_client_secret:
            resp = http.post(f"{host}/oidc/v1/token", data={"grant_type": "client_credentials", "scope": "all-apis"},
                             auth=(settings.databricks_client_id, settings.databricks_client_secret))
            if resp.status_code == 200:
                token = resp.json()["access_token"]
                line("OK", "service principal OAuth token", "scope all-apis granted")
            else:
                ok = False
                line("FAIL", "service principal OAuth token", f"HTTP {resp.status_code}: {resp.text[:200]}")
        elif token:
            line("INFO", "using static DATABRICKS_TOKEN", f"prefix={token[:4]}... length={len(token)}")
        else:
            ok = False
            line("FAIL", "credentials", "no DATABRICKS_TOKEN and no client id/secret")

        if token:
            headers = {"Authorization": f"Bearer {token}"}
            me = http.get(f"{host}/api/2.0/preview/scim/v2/Me", headers=headers)
            if me.status_code == 200:
                line("OK", "identity (SCIM Me)", str(me.json().get("userName") or me.json().get("displayName")))
            else:
                ok = False
                line("FAIL", "identity (SCIM Me)", f"HTTP {me.status_code}: {me.text[:200]}")
            if settings.genie_space_id:
                space = http.get(f"{host}/api/2.0/genie/spaces/{settings.genie_space_id}", headers=headers)
                if space.status_code == 200:
                    line("OK", "genie space", space.json().get("title", settings.genie_space_id))
                else:
                    ok = False
                    line("FAIL", "genie space", f"HTTP {space.status_code}: {space.text[:200]}")
    return 0 if ok else 1

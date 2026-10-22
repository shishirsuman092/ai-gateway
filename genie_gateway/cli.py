"""Command line helpers. Usage:

    python -m genie_gateway add-pat --role user --tools genie,jira [--name "Alice"]
    python -m genie_gateway add-pat --role admin --tools genie --token-env MY_PAT

The PAT is read from --token-env (env var), else a hidden prompt. It is never echoed,
logged or stored. The gateway asks Databricks who owns it, then creates or updates that account.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import sys

from .app import Services
from .config import Settings
from .rbac import KNOWN_TOOLS, ROLES


def add_pat(
    settings: Settings,
    pat: str,
    *,
    role: str,
    tools: list[str],
    name: str = "",
    databricks_http=None,
) -> dict:
    """Register the owner of a PAT directly against the database (no HTTP server needed)."""
    services = Services(settings, databricks_http=databricks_http)
    return asyncio.run(services.auth.register_pat_account(pat, role=role, tools=tools, name=name))


def _parse_tools(raw: str) -> list[str]:
    tools = [t.strip() for t in raw.split(",") if t.strip()]
    unknown = [t for t in tools if t not in KNOWN_TOOLS]
    if unknown:
        raise SystemExit(f"unknown tool(s): {', '.join(unknown)}; choose from {', '.join(KNOWN_TOOLS)}")
    return tools


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m genie_gateway")
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add-pat", help="add or update the account that owns a Databricks PAT")
    add.add_argument("--role", choices=ROLES, default="user")
    add.add_argument("--tools", default="", help=f"comma list: {','.join(KNOWN_TOOLS)}")
    add.add_argument("--name", default="")
    add.add_argument("--token-env", help="name of the environment variable holding the PAT")
    sub.add_parser("diagnose", help="check config, local accounts and Databricks access; prints each result")
    args = parser.parse_args(argv)

    if args.command == "diagnose":
        from .diagnose import run_diagnose
        return run_diagnose(Settings.from_env())

    if args.token_env:
        pat = os.environ.get(args.token_env, "")
    elif sys.stdin.isatty():
        pat = getpass.getpass("Databricks PAT (input hidden): ")
    else:
        pat = sys.stdin.readline().strip()
    if not pat:
        print("error: no token provided", file=sys.stderr)
        return 2

    settings = Settings.from_env()
    try:
        result = add_pat(settings, pat.strip(), role=args.role, tools=_parse_tools(args.tools), name=args.name)
    except Exception as exc:  # ValueError, UserError or AuthError (workspace rejected the PAT)
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({k: result[k] for k in ("action", "email", "kind", "role", "tools")}, indent=2))
    return 0

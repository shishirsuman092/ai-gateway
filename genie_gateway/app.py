"""Wires everything together: MCP tools, HTTP auth/admin routes, bearer-token middleware."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import httpx
from urllib.parse import urlparse

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from .audit import AuditLog
from .auth import AuthError, AuthService
from .observability import Metrics, TokenBucketLimiter, new_request_id, request_id_var
from .oauth import OAuthService
from .oauth_http import OAUTH_PUBLIC_PATHS, build_oauth_routes
from .auth.databricks import looks_like_pat
from .config import Settings
from .auth.local import hash_password
from .db import Database
from .chats import ChatNotFound, ChatService
from .databricks_auth import ServicePrincipalAuth
from .directory import DatabricksDirectory, DirectoryError
from .jobs import JobError, JobNotFound, JobService
from .rbac import Forbidden, require_admin, require_tool
from .summarizer import Summarizer
from .tools import ToolRegistry, UnknownTool
from .users import UserError, UserService

log = logging.getLogger("genie_gateway")
access_log = logging.getLogger("genie_gateway.access")
auth_log = logging.getLogger("genie_gateway.auth")

# Paths that do not need a bearer token.
PUBLIC_PATHS = {("POST", "/auth/login"), ("GET", "/health"), ("GET", "/ready")} | OAUTH_PUBLIC_PATHS

SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"cache-control", b"no-store"),
    (b"referrer-policy", b"no-referrer"),
]


def _with_headers(send: Any, request_id: str, *, https: bool = False) -> Any:
    """Wrap ASGI send: add security headers, HSTS when served over https, and the request ID."""
    extra = SECURITY_HEADERS + [(b"x-request-id", request_id.encode())]
    if https:
        extra.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))

    async def wrapped(message: dict) -> None:
        if message["type"] == "http.response.start":
            message = {**message, "headers": list(message.get("headers", [])) + extra}
        await send(message)

    return wrapped
# Paths allowed while a user must still change a demo password.
PASSWORD_CHANGE_PATHS = {("POST", "/auth/change-password"), ("GET", "/api/me"), ("POST", "/auth/logout")}


class Services:
    """Everything the app needs, built once from Settings. Tests can build it with custom Settings."""

    def __init__(self, settings: Settings, *, databricks_http: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self.db = Database(settings.db_path)
        self.users = UserService(self.db)
        self.audit = AuditLog(self.db)
        self.auth = AuthService(settings, self.users, databricks_http=databricks_http, audit=self.audit)
        self.registry = ToolRegistry.from_settings(settings)
        self.chats = ChatService(self.db)
        self.summarizer = Summarizer(settings)
        self.jobs = JobService(
            self.db,
            self.registry,
            audit=self.audit,
            guardrails_enabled=settings.guardrails_enabled,
            max_question_chars=settings.max_question_chars,
            chats=self.chats,
            summarizer=self.summarizer,
            auth_mode=settings.databricks_auth_mode,
            encryption_key=settings.gateway_encryption_key,
        )
        self.directory_credentials = ServicePrincipalAuth(
            settings.databricks_host,
            static_token=settings.databricks_token,
            client_id=settings.databricks_client_id,
            client_secret=settings.databricks_client_secret,
            http=databricks_http,
        ) if settings.databricks_host and settings.service_credentials_present else None
        self._databricks_http = databricks_http
        self.oauth = OAuthService(settings, self.db, self.audit) if settings.oauth_enabled else None
        self.auth.oauth = self.oauth
        self.metrics = Metrics()
        self.ip_limiter = TokenBucketLimiter(settings.rate_limit_per_minute)
        self.user_limiter = TokenBucketLimiter(settings.rate_limit_per_minute)

        if settings.auth_provider == "local":
            seed_hash = hash_password(settings.admin_default_password)
        else:
            seed_hash = None  # SSO admin signs in through the IdP; no local password
        self.users.seed_admin(settings.admin_email, provider=settings.auth_provider, password_hash=seed_hash)
        recovered = self.jobs.recover()
        if recovered:
            log.warning("marked %d unfinished job(s) as failed after restart", recovered)


def _json_error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


class BearerAuthMiddleware:
    """Pure ASGI middleware: checks the bearer token and stores the user row in scope['state']."""

    def __init__(self, app: Any, services: Services) -> None:
        self.app = app
        self.services = services

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = new_request_id(dict(scope["headers"]).get(b"x-request-id", b"").decode() or None)
        request_id_var.set(request_id)
        scope.setdefault("state", {})["request_id"] = request_id
        https = self.services.settings.base_url.startswith("https://")
        started = time.monotonic()
        status: dict[str, int] = {}

        async def capture(message: dict) -> None:
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        try:
            await self._handle(scope, receive, _with_headers(capture, request_id, https=https))
        finally:
            # One access line per request: the first place to look when a client cannot connect.
            client_ip = (scope.get("client") or ("?", 0))[0]
            access_log.info(
                "%s %s status=%s ms=%d ip=%s user=%s ua=%s",
                scope["method"], scope["path"], status.get("code", "-"),
                int((time.monotonic() - started) * 1000), client_ip,
                (scope.get("state") or {}).get("user", {}).get("email", "-"),
                dict(scope["headers"]).get(b"user-agent", b"-").decode("latin-1")[:80],
            )

    async def _handle(self, scope: dict, receive: Any, send: Any) -> None:
        method, path = scope["method"], scope["path"]
        client_ip = (scope.get("client") or ("unknown", 0))[0]
        wait = self.services.ip_limiter.check(f"ip:{client_ip}")
        if wait:
            self.services.metrics.inc("genie_gateway_rate_limited_total", scope="ip")
            await _rate_limited(wait)(scope, receive, send)
            return

        if (method, path) in PUBLIC_PATHS:
            await self.app(scope, receive, send)
            return

        header = dict(scope["headers"]).get(b"authorization", b"").decode()
        if not header.lower().startswith("bearer "):
            auth_log.info("no bearer token path=%s ip=%s", path, client_ip)
            await _challenge(self.services, "missing bearer token")(scope, receive, send)
            return
        try:
            user = await self.services.auth.authenticate(header[7:].strip())
        except AuthError as exc:
            self.services.metrics.inc("genie_gateway_auth_failures_total")
            kind = "pat" if looks_like_pat(header[7:].strip()) else "token"
            auth_log.warning("auth rejected kind=%s path=%s ip=%s reason=%s", kind, path, client_ip, exc)
            await _challenge(self.services, str(exc))(scope, receive, send)
            return

        wait = self.services.user_limiter.check(f"user:{user['email']}")
        if wait:
            self.services.metrics.inc("genie_gateway_rate_limited_total", scope="user")
            await _rate_limited(wait)(scope, receive, send)
            return

        # The forced password change applies to password logins only; PAT callers never use one.
        is_pat = looks_like_pat(header[7:].strip())
        if user["must_change_password"] and not is_pat and (method, path) not in PASSWORD_CHANGE_PATHS:
            await _json_error(403, "password change required before using the gateway")(scope, receive, send)
            return

        scope.setdefault("state", {})["user"] = user
        scope["state"]["raw_token"] = header[7:].strip()  # user_pat mode forwards a caller PAT to Genie
        await self.app(scope, receive, send)


def _challenge(services: "Services", message: str) -> JSONResponse:
    """401 with an RFC 6750 / MCP challenge so OAuth clients know where to get a token."""
    headers = {}
    if services.oauth is not None:
        headers["WWW-Authenticate"] = services.oauth.challenge_header()
    return JSONResponse({"error": message}, status_code=401, headers=headers)


def _rate_limited(wait_seconds: float) -> JSONResponse:
    return JSONResponse(
        {"error": "rate limit exceeded"},
        status_code=429,
        headers={"Retry-After": str(max(1, int(wait_seconds + 0.999)))},
    )


def _user_of(request: Request) -> dict[str, Any]:
    user = getattr(request.state, "user", None)
    if user is None:
        raise AuthError("not authenticated")
    return user


def build_mcp(services: Services) -> FastMCP:
    mcp = FastMCP(
        "genie-gateway",
        instructions=(
            "Ask questions in plain text. submit_query returns a job_id at once; "
            "call get_query_result with wait_seconds to get the answer. "
            "Prefix with genie:, slack: or jira: to pick a tool, or pass tool=."
        ),
        stateless_http=True,
        json_response=True,
        # DNS-rebinding guard: accept only the public host (behind a tunnel or proxy) and local addresses.
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=sorted({urlparse(services.settings.base_url).netloc, "127.0.0.1:*", "localhost:*"}),
            allowed_origins=[services.settings.base_url],
        ),
    )

    def caller(ctx: Context) -> dict[str, Any]:
        request = ctx.request_context.request
        user = getattr(request.state, "user", None) if request is not None else None
        if user is None:
            raise AuthError("not authenticated")
        return user

    def caller_pat(ctx: Context) -> str | None:
        request = ctx.request_context.request
        token = getattr(request.state, "raw_token", None) if request is not None else None
        return token if token and looks_like_pat(token) else None

    @mcp.tool()
    def submit_query(
        question: str,
        ctx: Context,
        tool: str | None = None,
        conversation_id: str | None = None,
        chat_context: str | None = None,
        context_summary: str | None = None,
    ) -> dict:
        """Submit a plain-text question. Returns a job_id immediately.

        tool: genie | slack | jira. conversation_id: continue a saved chat (omit to start one).
        chat_context: earlier chat text; the gateway summarizes it before Genie sees it.
        context_summary: a summary you already made (skips the gateway summarizer).
        """
        return services.jobs.submit(
            caller(ctx), question, tool,
            conversation_id=conversation_id, chat_context=chat_context,
            context_summary=context_summary, user_token=caller_pat(ctx),
        )

    @mcp.tool()
    def list_conversations(ctx: Context, limit: int = 20) -> list:
        """List your saved chats, newest first."""
        return services.chats.list_for(caller(ctx), limit)

    @mcp.tool()
    def get_conversation(conversation_id: str, ctx: Context) -> dict:
        """Get a saved chat with all messages sent and answers received."""
        try:
            return services.chats.messages(caller(ctx), conversation_id)
        except ChatNotFound as exc:
            raise JobError(str(exc)) from exc

    @mcp.tool()
    async def get_query_result(job_id: str, ctx: Context, wait_seconds: int = 0) -> dict:
        """Get a job's status and result. wait_seconds (max 60) long-polls until it finishes."""
        return await services.jobs.wait(caller(ctx), job_id, wait_seconds)

    @mcp.tool()
    def list_my_queries(ctx: Context, limit: int = 10) -> list:
        """List your most recent jobs."""
        return services.jobs.list_for(caller(ctx), limit)

    @mcp.tool()
    def list_available_tools(ctx: Context) -> dict:
        """List the tools you are allowed to use."""
        user = caller(ctx)
        allowed = [t for t in services.registry.names if _can(user, t)]
        return {"tools": allowed, "role": user["role"]}

    return mcp


def _can(user: dict[str, Any], tool: str) -> bool:
    try:
        require_tool(user, tool)
        return True
    except Forbidden:
        return False


def build_routes(services: Services) -> list[Route]:
    async def health(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True, "auth_provider": services.settings.auth_provider})

    async def ready(request: Request) -> JSONResponse:
        # Readiness: the database answers. Used by load balancers before routing traffic.
        if not services.db.ping():
            return _json_error(503, "database unavailable")
        return JSONResponse({"ready": True, "schema_version": services.db.schema_version})

    async def logout(request: Request) -> JSONResponse:
        token = request.headers.get("authorization", "")[7:].strip()
        try:
            services.auth.logout(token)
        except AuthError as exc:
            return _json_error(400, str(exc))
        return JSONResponse({"ok": True})

    async def metrics(request: Request) -> Response:
        try:
            require_admin(_user_of(request))
        except Forbidden as exc:
            return _json_error(403, str(exc))
        return PlainTextResponse(services.metrics.render())

    async def account_from_pat(request: Request) -> JSONResponse:
        body = await _body(request)

        async def action() -> JSONResponse:
            try:
                result = await services.auth.register_pat_account(
                    body.get("pat", ""),
                    role=body.get("role", "user"),
                    tools=body.get("tools") or [],
                    name=body.get("name", ""),
                )
            except AuthError as exc:
                return _json_error(400, str(exc))
            return JSONResponse(result, status_code=201 if result["action"] == "created" else 200)

        try:
            require_admin(_user_of(request))
        except AuthError as exc:
            return _json_error(401, str(exc))
        except Forbidden as exc:
            return _json_error(403, str(exc))
        try:
            return await action()
        except (UserError, ValueError) as exc:
            return _json_error(400, str(exc))

    async def audit_list(request: Request) -> JSONResponse:
        params = request.query_params

        def action() -> JSONResponse:
            return JSONResponse(services.audit.list(
                limit=int(params.get("limit", "100")),
                actor=params.get("actor"),
                action=params.get("action"),
            ))

        return _admin(request, action)

    async def login(request: Request) -> JSONResponse:
        body = await _body(request)
        try:
            return JSONResponse(services.auth.login(body.get("email", ""), body.get("password", "")))
        except AuthError as exc:
            status = 404 if services.auth.provider != "local" else 401
            return _json_error(status, str(exc))

    async def change_password(request: Request) -> JSONResponse:
        body = await _body(request)
        try:
            services.auth.change_password(_user_of(request), body.get("old_password", ""), body.get("new_password", ""))
        except (AuthError, ValueError) as exc:
            return _json_error(400, str(exc))
        return JSONResponse({"ok": True})

    async def list_users(request: Request) -> JSONResponse:
        return _admin(request, lambda: JSONResponse(services.users.list()))

    async def create_user(request: Request) -> JSONResponse:
        body = await _body(request)

        def action() -> JSONResponse:
            password = body.get("password")
            kind = body.get("kind", "human")
            if kind == "service" and password:
                raise UserError("service accounts cannot have a password; they authenticate with a PAT")
            user = services.users.create(
                body.get("email", ""),
                provider="databricks" if kind == "service" else (services.auth.provider if not password else "local"),
                name=body.get("name", ""),
                role=body.get("role", "user"),
                tools=body.get("tools", []),
                password_hash=hash_password(password) if password else None,
                must_change_password=bool(password),
                kind=kind,
            )
            return JSONResponse(user, status_code=201)

        return _admin(request, action)

    async def update_user(request: Request) -> JSONResponse:
        body = await _body(request)
        email = request.path_params["email"]

        def action() -> JSONResponse:
            if "password" in body and body["password"]:
                services.users.set_password_hash(email, hash_password(body["password"]), must_change=True)
            user = services.users.update(
                email,
                role=body.get("role"),
                tools=body.get("tools"),
                is_active=body.get("is_active"),
                name=body.get("name"),
            )
            return JSONResponse(user)

        return _admin(request, action)

    async def api_me(request: Request) -> JSONResponse:
        user = _user_of(request)
        return JSONResponse({
            "email": user["email"],
            "name": user["name"],
            "role": user["role"],
            "kind": user["kind"],
            "must_change_password": user["must_change_password"],
            "tools": services.registry.names if user["role"] == "admin" else user["tools"],
        })

    async def api_query(request: Request) -> JSONResponse:
        body = await _body(request)
        raw = getattr(request.state, "raw_token", None)
        try:
            job = services.jobs.submit(
                _user_of(request), body.get("question", ""), body.get("tool") or None,
                conversation_id=body.get("conversation_id") or None,
                chat_context=body.get("chat_context") or None,
                context_summary=body.get("context_summary") or None,
                user_token=raw if raw and looks_like_pat(raw) else None,
            )
        except Forbidden as exc:
            return _json_error(403, str(exc))
        except JobError as exc:
            return _json_error(400, str(exc))
        return JSONResponse(job, status_code=202)

    async def api_conversations(request: Request) -> JSONResponse:
        limit = int(request.query_params.get("limit", "20") or 20)
        return JSONResponse(services.chats.list_for(_user_of(request), limit))

    async def api_conversation(request: Request) -> JSONResponse:
        try:
            return JSONResponse(services.chats.messages(_user_of(request), request.path_params["conversation_id"]))
        except ChatNotFound as exc:
            return _json_error(404, str(exc))

    def _directory() -> DatabricksDirectory:
        if services.directory_credentials is None:
            raise UserError("directory sync needs DATABRICKS_HOST and service credentials")
        return DatabricksDirectory(services.settings, services.directory_credentials, http=services._databricks_http)

    async def directory_list(request: Request) -> JSONResponse:
        include_sp = request.query_params.get("include_service_principals", "true").lower() != "false"

        async def action() -> JSONResponse:
            try:
                entries = await _directory().list_all(include_service_principals=include_sp)
            except DirectoryError as exc:
                return _json_error(502, str(exc))
            return JSONResponse({
                "scope": _directory().scope,
                "count": len(entries),
                "entries": [e.__dict__ for e in entries],
            })

        return await _admin_async(request, action)

    async def directory_sync(request: Request) -> JSONResponse:
        """Create gateway accounts for directory entries that do not exist yet. Never overwrites."""
        body = await _body(request)

        async def action() -> JSONResponse:
            try:
                entries = await _directory().list_all(
                    include_service_principals=bool(body.get("include_service_principals", True)))
            except DirectoryError as exc:
                return _json_error(502, str(exc))
            role = body.get("role", "user")
            tools = body.get("tools") or []
            dry_run = bool(body.get("dry_run", False))
            created, existing, inactive = [], 0, []
            for entry in entries:
                if not entry.active:
                    inactive.append(entry.email)
                    continue
                if services.users.get(entry.email) is not None:
                    existing += 1
                    continue
                if not dry_run:
                    services.users.create(
                        entry.email,
                        provider="databricks",
                        name=entry.name,
                        role=role,
                        tools=tools,
                        kind=entry.kind,
                    )
                created.append({"email": entry.email, "kind": entry.kind})
            services.audit.record(
                "directory.sync",
                outcome="success",
                actor=_user_of(request)["email"],
                detail={"scope": _directory().scope, "created": len(created), "existing": existing,
                        "inactive": len(inactive), "dry_run": dry_run},
            )
            return JSONResponse({"scope": _directory().scope, "dry_run": dry_run, "created": created,
                                 "existing": existing, "skipped_inactive": inactive})

        return await _admin_async(request, action)

    async def api_job(request: Request) -> JSONResponse:
        wait = int(request.query_params.get("wait", "0") or 0)
        try:
            job = await services.jobs.wait(_user_of(request), request.path_params["job_id"], wait)
        except JobNotFound as exc:
            return _json_error(404, str(exc))
        return JSONResponse(job)

    async def api_jobs(request: Request) -> JSONResponse:
        limit = int(request.query_params.get("limit", "20") or 20)
        return JSONResponse(services.jobs.list_for(_user_of(request), limit))

    return [
        Route("/api/me", api_me, methods=["GET"]),
        Route("/api/query", api_query, methods=["POST"]),
        Route("/api/jobs/{job_id}", api_job, methods=["GET"]),
        Route("/api/jobs", api_jobs, methods=["GET"]),
        Route("/api/conversations", api_conversations, methods=["GET"]),
        Route("/api/conversations/{conversation_id}", api_conversation, methods=["GET"]),
        Route("/admin/databricks/directory", directory_list, methods=["GET"]),
        Route("/admin/databricks/directory/sync", directory_sync, methods=["POST"]),
        Route("/health", health, methods=["GET"]),
        Route("/ready", ready, methods=["GET"]),
        Route("/metrics", metrics, methods=["GET"]),
        Route("/auth/login", login, methods=["POST"]),
        Route("/auth/logout", logout, methods=["POST"]),
        Route("/auth/change-password", change_password, methods=["POST"]),
        Route("/admin/audit", audit_list, methods=["GET"]),
        Route("/admin/accounts/from-pat", account_from_pat, methods=["POST"]),
        Route("/admin/users", list_users, methods=["GET"]),
        Route("/admin/users", create_user, methods=["POST"]),
        Route("/admin/users/{email}", update_user, methods=["PATCH"]),
    ]


async def _admin_async(request: Request, action: Any) -> JSONResponse:
    """Async variant of _admin for actions that call Databricks."""
    try:
        require_admin(_user_of(request))
        return await action()
    except AuthError as exc:
        return _json_error(401, str(exc))
    except Forbidden as exc:
        return _json_error(403, str(exc))
    except (UserError, ValueError) as exc:
        return _json_error(400, str(exc))


def _admin(request: Request, action: Any) -> JSONResponse:
    """Run an admin-only action, mapping domain errors to HTTP status codes."""
    try:
        require_admin(_user_of(request))
        return action()
    except AuthError as exc:
        return _json_error(401, str(exc))
    except Forbidden as exc:
        return _json_error(403, str(exc))
    except (UserError, ValueError) as exc:
        return _json_error(400, str(exc))


async def _body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def create_app(settings: Settings | None = None, *, databricks_http: httpx.AsyncClient | None = None):
    """Build the ASGI app: MCP at /mcp, plus auth and admin routes, all behind bearer auth.

    databricks_http lets tests stub the workspace SCIM endpoint used to verify PATs.
    """
    settings = settings or Settings.from_env()
    services = Services(settings, databricks_http=databricks_http)
    mcp = build_mcp(services)
    app = mcp.streamable_http_app()
    for route in build_routes(services):
        app.routes.append(route)
    if services.oauth is not None:
        for route in build_oauth_routes(services):
            app.routes.append(route)
    app.add_middleware(BearerAuthMiddleware, services=services)
    if settings.cors_origins:
        # Added last, so it is the outermost layer and answers browser preflight without a token.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
            expose_headers=["X-Request-ID"],
        )
    app.state.services = services
    return app

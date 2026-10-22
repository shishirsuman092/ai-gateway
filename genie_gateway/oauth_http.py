"""HTTP routes for the OAuth authorization server and discovery documents."""

from __future__ import annotations

import html
import json
import logging
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .auth import AuthError
from .auth.databricks import looks_like_pat
from .oauth import OAuthError

log = logging.getLogger("genie_gateway.oauth")

PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"

OAUTH_PUBLIC_PATHS = {
    ("GET", "/.well-known/oauth-protected-resource"),
    ("GET", "/.well-known/oauth-authorization-server"),
    ("POST", "/oauth/register"),
    ("POST", "/oauth/token"),
    ("GET", "/oauth/authorize"),
    ("POST", "/oauth/authorize"),
}


def _oauth_error(status: int, code: str, description: str) -> JSONResponse:
    return JSONResponse({"error": code, "error_description": description}, status_code=status)


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        data = json.loads(await request.body() or b"{}")
    except json.JSONDecodeError:
        log.warning("register: body is not JSON")
        return {}
    return data if isinstance(data, dict) else {}


async def _form_body(request: Request) -> dict[str, str]:
    raw = (await request.body()).decode("utf-8", "replace")
    return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}


def _redirect_host(uri: str) -> str:
    return urlparse(uri).netloc or "?"


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:420px;margin:48px auto;padding:0 16px;color:#111}}
label{{display:block;margin-top:14px;font-weight:600}}
input{{width:100%;box-sizing:border-box;padding:9px;margin-top:4px;font-size:15px}}
button{{margin-top:20px;padding:10px 18px;font-size:15px;cursor:pointer}}
.err{{background:#fdecea;color:#611;padding:10px;border-radius:4px;margin-top:12px}}
.hint{{color:#555;font-size:13px;margin-top:6px}}
</style></head><body>{body}</body></html>"""
    return HTMLResponse(doc, status_code=status, headers={"Content-Security-Policy": PAGE_CSP})


def _login_form(params: dict[str, str], csrf: str, *, client_name: str, password_login: bool,
                error: str = "") -> str:
    # Carry every authorization parameter back on POST. response_type and code_challenge_method
    # are fixed values, so they are always included even though they are not in `params`.
    fields = {
        "client_id": params["client_id"],
        "redirect_uri": params["redirect_uri"],
        "response_type": "code",
        "code_challenge": params["code_challenge"],
        "code_challenge_method": "S256",
        "state": params.get("state", ""),
    }
    hidden = "".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
        for k, v in fields.items()
    )
    error_html = f'<div class="err">{html.escape(error)}</div>' if error else ""
    password_fields = (
        '<label>Email<input name="email" type="email" autocomplete="username"></label>'
        '<label>Password<input name="password" type="password" autocomplete="current-password"></label>'
        '<label>New password (only if your account requires one, 8+ characters)'
        '<input name="new_password" type="password" autocomplete="new-password"></label>'
        '<div class="hint">or paste a Databricks personal access token below</div>'
        if password_login else
        '<div class="hint">Password login is disabled for this server. Use a Databricks personal access token.</div>'
    )
    return f"""<h2>Connect {html.escape(client_name or 'MCP client')} to Genie gateway</h2>
{error_html}
<form method="post" action="/oauth/authorize">
{hidden}
<input type="hidden" name="csrf" value="{html.escape(csrf)}">
{password_fields}
<label>Databricks PAT<input name="pat" type="password" autocomplete="off" placeholder="dapi..."></label>
<button type="submit">Allow</button>
</form>"""


def build_oauth_routes(services: Any) -> list[Route]:
    oauth = services.oauth
    auth = services.auth

    async def protected_resource(request: Request) -> JSONResponse:
        return JSONResponse(oauth.protected_resource_metadata())

    async def authorization_server(request: Request) -> JSONResponse:
        return JSONResponse(oauth.authorization_server_metadata())

    async def register(request: Request) -> JSONResponse:
        body = await _json_body(request)
        uris = body.get("redirect_uris") or []
        if not isinstance(uris, list) or not all(isinstance(u, str) for u in uris):
            log.warning("register rejected: redirect_uris is not a list of strings")
            return _oauth_error(400, "invalid_redirect_uri", "redirect_uris must be a list of strings")
        try:
            client = oauth.register_client(str(body.get("client_name", "")), uris)
        except OAuthError as exc:
            log.warning("register rejected: %s (%s) hosts=%s", exc.code, exc.description,
                        [_redirect_host(u) for u in uris])
            status = 403 if exc.code == "access_denied" else 400
            return _oauth_error(status, exc.code, exc.description)
        log.info("register ok client=%s name=%r hosts=%s", client["client_id"][:8],
                 client["client_name"], [_redirect_host(u) for u in uris])
        return JSONResponse(client, status_code=201)

    async def authorize_get(request: Request) -> Response:
        params = dict(request.query_params)
        try:
            cleaned = oauth.validate_authorize(params)
        except OAuthError as exc:
            log.warning("authorize GET rejected: %s (%s) client=%s", exc.code, exc.description,
                        params.get("client_id", "")[:8])
            return _page("Authorization error", f'<div class="err">{html.escape(exc.description)}</div>', 400)
        log.info("authorize page shown client=%s name=%r password_login=%s", cleaned["client_id"][:8],
                 cleaned["client_name"], auth.provider == "local")
        csrf = oauth.csrf_token(cleaned)
        form = _login_form(cleaned, csrf, client_name=cleaned["client_name"],
                           password_login=auth.provider == "local")
        return _page("Connect to Genie gateway", form)

    async def authorize_post(request: Request) -> Response:
        data = await _form_body(request)
        try:
            cleaned = oauth.validate_authorize(data)
        except OAuthError as exc:
            log.warning("authorize POST rejected: %s (%s) client=%s", exc.code, exc.description,
                        data.get("client_id", "")[:8])
            return _page("Authorization error", f'<div class="err">{html.escape(exc.description)}</div>', 400)

        client = cleaned["client_id"][:8]

        def reshow(message: str) -> Response:
            log.warning("authorize login failed client=%s reason=%s", client, message)
            csrf = oauth.csrf_token(cleaned)
            return _page("Connect to Genie gateway",
                         _login_form(cleaned, csrf, client_name=cleaned["client_name"],
                                     password_login=auth.provider == "local", error=message), 401)

        if not oauth.check_csrf(cleaned, data.get("csrf", "")):
            log.warning("authorize POST csrf mismatch client=%s (form expired or tampered)", client)
            return _page("Form expired", '<div class="err">The sign-in form expired. Start again from your client.</div>', 400)

        pat = data.get("pat", "").strip()
        try:
            if pat:
                if not looks_like_pat(pat):
                    return reshow("That is not a Databricks personal access token (it starts with dapi).")
                log.info("authorize with PAT client=%s", client)
                user = await auth.authenticate(pat)
            else:
                email = data.get("email", "").strip().lower()
                if auth.provider != "local":
                    return reshow("Password login is disabled. Paste a Databricks personal access token.")
                log.info("authorize with password client=%s email=%s", client, email)
                auth.login(email, data.get("password", ""))
                user = auth.users.get(email)
                if user is None:
                    return reshow("invalid email or password")
                if user["must_change_password"]:
                    new_password = data.get("new_password", "")
                    if not new_password:
                        return reshow("Your account requires a new password. Enter one in the New password field.")
                    log.info("authorize: changing required password email=%s", email)
                    auth.change_password(user, data.get("password", ""), new_password)
                    user = auth.users.get(email)
        except AuthError as exc:
            return reshow(str(exc))
        except ValueError as exc:
            return reshow(str(exc))

        code = oauth.issue_code(cleaned, user["email"])
        log.info("authorize approved client=%s user=%s redirect_host=%s", client, user["email"],
                 _redirect_host(cleaned["redirect_uri"]))
        query = {"code": code}
        if cleaned["state"]:
            query["state"] = cleaned["state"]
        separator = "&" if "?" in cleaned["redirect_uri"] else "?"
        return RedirectResponse(f"{cleaned['redirect_uri']}{separator}{urlencode(query)}", status_code=302)

    async def token(request: Request) -> JSONResponse:
        params = await _form_body(request)
        grant = params.get("grant_type", "")
        client = params.get("client_id", "")[:8]
        try:
            if grant == "authorization_code":
                result = oauth.exchange_code(params)
            elif grant == "refresh_token":
                result = oauth.refresh(params)
            else:
                log.warning("token rejected: unsupported grant_type=%r client=%s", grant, client)
                return _oauth_error(400, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
        except OAuthError as exc:
            log.warning("token rejected: grant=%s client=%s error=%s (%s)", grant, client, exc.code, exc.description)
            return _oauth_error(400, exc.code, exc.description)
        log.info("token issued grant=%s client=%s", grant, client)
        return JSONResponse(result, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    return [
        Route("/.well-known/oauth-protected-resource", protected_resource, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", authorization_server, methods=["GET"]),
        Route("/oauth/register", register, methods=["POST"]),
        Route("/oauth/authorize", authorize_get, methods=["GET"]),
        Route("/oauth/authorize", authorize_post, methods=["POST"]),
        Route("/oauth/token", token, methods=["POST"]),
    ]

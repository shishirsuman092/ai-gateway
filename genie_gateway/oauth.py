"""OAuth 2.1 authorization server for MCP clients (authorization code + PKCE, refresh tokens, DCR).

Implements the MCP authorization flow:
  - /.well-known/oauth-protected-resource  (RFC 9728): tells the client which server issues tokens.
  - /.well-known/oauth-authorization-server (RFC 8414): endpoints and capabilities.
  - /oauth/register   (RFC 7591 dynamic client registration; public clients only).
  - /oauth/authorize  login page: the user signs in with a Databricks PAT (any provider) or,
                      with AUTH_PROVIDER=local, email and password. Then an auth code is issued.
  - /oauth/token      exchanges the code (PKCE S256 required) or a refresh token.

Access tokens are HS256 JWTs signed with JWT_SECRET, with iss = base URL and aud = <base>/mcp.
They are revocable by jti (same revocation table as logout). Refresh tokens rotate on every use.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import uuid
from typing import Any
from urllib.parse import urlparse

import jwt

from .audit import AuditLog
from .auth.base import AuthError, Principal
from .config import Settings
from .db import Database

AUTH_CODE_SECONDS = 60
SCOPE = "mcp"
CSRF_SECONDS = 900


class OAuthError(Exception):
    """Protocol error. `code` is the OAuth error code returned to the client."""

    def __init__(self, code: str, description: str = "") -> None:
        super().__init__(description or code)
        self.code = code
        self.description = description or code


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _b64url_sha256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def is_allowed_redirect(uri: str) -> bool:
    """https always; http only for loopback (native apps and local tools)."""
    parsed = urlparse(uri)
    if parsed.scheme == "https" and parsed.netloc:
        return not parsed.fragment
    if parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1"):
        return not parsed.fragment
    return False


class OAuthService:
    def __init__(self, settings: Settings, db: Database, audit: AuditLog | None = None) -> None:
        self.settings = settings
        self.db = db
        self.audit = audit
        self.issuer = settings.base_url
        self.resource = f"{settings.base_url}/mcp"

    # --- metadata ---------------------------------------------------------------

    def protected_resource_metadata(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [SCOPE],
        }

    def authorization_server_metadata(self) -> dict[str, Any]:
        meta = {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/oauth/authorize",
            "token_endpoint": f"{self.issuer}/oauth/token",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [SCOPE],
        }
        if self.settings.oauth_allow_dynamic_registration:
            meta["registration_endpoint"] = f"{self.issuer}/oauth/register"
        return meta

    def challenge_header(self) -> str:
        return f'Bearer resource_metadata="{self.issuer}/.well-known/oauth-protected-resource", scope="{SCOPE}"'

    # --- dynamic client registration ----------------------------------------------

    def register_client(self, client_name: str, redirect_uris: list[str]) -> dict[str, Any]:
        if not self.settings.oauth_allow_dynamic_registration:
            raise OAuthError("access_denied", "dynamic client registration is disabled")
        if not redirect_uris or not all(is_allowed_redirect(u) for u in redirect_uris):
            raise OAuthError("invalid_redirect_uri", "redirect_uris must be https (or http loopback)")
        client_id = uuid.uuid4().hex
        now = time.time()
        self.db.execute(
            "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at) VALUES (?, ?, ?, ?)",
            (client_id, client_name[:120], " ".join(redirect_uris), now),
        )
        self._audit("oauth.client_registered", None, target=client_id, detail={"name": client_name[:120]})
        return {
            "client_id": client_id,
            "client_id_issued_at": int(now),
            "client_name": client_name[:120],
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        row = self.db.one("SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,))
        if row is None:
            return None
        row["redirect_uris"] = row["redirect_uris"].split(" ")
        return row

    # --- authorization request validation ------------------------------------------

    def validate_authorize(self, params: dict[str, str]) -> dict[str, str]:
        """Return the cleaned request. Raises OAuthError. Errors are shown to the user, never redirected."""
        client = self.get_client(params.get("client_id", ""))
        if client is None:
            raise OAuthError("invalid_client", "unknown client_id")
        redirect_uri = params.get("redirect_uri", "")
        if redirect_uri not in client["redirect_uris"]:
            raise OAuthError("invalid_redirect_uri", "redirect_uri is not registered for this client")
        if params.get("response_type") != "code":
            raise OAuthError("unsupported_response_type", "response_type must be code")
        if params.get("code_challenge_method") != "S256" or not params.get("code_challenge"):
            raise OAuthError("invalid_request", "PKCE with code_challenge_method=S256 is required")
        return {
            "client_id": client["client_id"],
            "client_name": client["client_name"],
            "redirect_uri": redirect_uri,
            "code_challenge": params["code_challenge"],
            "state": params.get("state", ""),
        }

    def issue_code(self, request: dict[str, str], user_email: str) -> str:
        code = secrets.token_urlsafe(32)
        self.db.execute(
            "INSERT INTO oauth_codes (code_hash, client_id, user_email, redirect_uri, code_challenge, expires_at, used) "
            "VALUES (?, ?, ?, ?, ?, ?, 0)",
            (_sha256(code), request["client_id"], user_email, request["redirect_uri"],
             request["code_challenge"], time.time() + AUTH_CODE_SECONDS),
        )
        self._audit("oauth.code_issued", "success", actor=user_email, target=request["client_id"])
        return code

    # --- token endpoint ---------------------------------------------------------------

    def exchange_code(self, params: dict[str, str]) -> dict[str, Any]:
        code = params.get("code", "")
        row = self.db.one("SELECT * FROM oauth_codes WHERE code_hash = ?", (_sha256(code),)) if code else None
        if row is None or row["used"] or row["expires_at"] < time.time():
            raise OAuthError("invalid_grant", "authorization code is invalid, used or expired")
        if params.get("client_id") != row["client_id"] or params.get("redirect_uri") != row["redirect_uri"]:
            raise OAuthError("invalid_grant", "client_id or redirect_uri does not match the code")
        verifier = params.get("code_verifier", "")
        if not (43 <= len(verifier) <= 128) or not hmac.compare_digest(_b64url_sha256(verifier), row["code_challenge"]):
            raise OAuthError("invalid_grant", "PKCE verification failed")
        # Single use: mark before issuing, so a replayed code fails.
        self.db.execute("UPDATE oauth_codes SET used = 1 WHERE code_hash = ?", (row["code_hash"],))
        return self._tokens(row["user_email"], row["client_id"])

    def refresh(self, params: dict[str, str]) -> dict[str, Any]:
        token = params.get("refresh_token", "")
        row = self.db.one("SELECT * FROM oauth_refresh_tokens WHERE token_hash = ?", (_sha256(token),)) if token else None
        if row is None or row["revoked"] or row["expires_at"] < time.time():
            raise OAuthError("invalid_grant", "refresh token is invalid, revoked or expired")
        if params.get("client_id") != row["client_id"]:
            raise OAuthError("invalid_grant", "refresh token was issued to another client")
        # Rotation: the old refresh token is revoked; a replay of it is refused.
        self.db.execute("UPDATE oauth_refresh_tokens SET revoked = 1 WHERE token_hash = ?", (row["token_hash"],))
        return self._tokens(row["user_email"], row["client_id"])

    def _tokens(self, user_email: str, client_id: str) -> dict[str, Any]:
        now = int(time.time())
        access_jti = uuid.uuid4().hex
        access = jwt.encode(
            {
                "iss": self.issuer,
                "aud": self.resource,
                "sub": user_email,
                "email": user_email,
                "client_id": client_id,
                "scope": SCOPE,
                "iat": now,
                "exp": now + self.settings.oauth_access_token_seconds,
                "jti": access_jti,
            },
            self.settings.jwt_secret,
            algorithm="HS256",
        )
        refresh = secrets.token_urlsafe(48)
        self.db.execute(
            "INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_email, expires_at, revoked) "
            "VALUES (?, ?, ?, ?, 0)",
            (_sha256(refresh), client_id, user_email, time.time() + self.settings.oauth_refresh_token_seconds),
        )
        self._audit("oauth.token_issued", "success", actor=user_email, target=client_id)
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.settings.oauth_access_token_seconds,
            "refresh_token": refresh,
            "scope": SCOPE,
        }

    # --- access token verification (called by AuthService) ------------------------

    def verify_access_token(self, token: str) -> Principal | None:
        """Return the principal for a token this server issued. None if the token is not ours.

        Raises AuthError for tokens that are ours but invalid (expired, wrong audience, revoked).
        """
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            return None
        if unverified.get("iss") != self.issuer:
            return None
        try:
            claims = jwt.decode(
                token,
                self.settings.jwt_secret,
                algorithms=["HS256"],
                issuer=self.issuer,
                audience=self.resource,
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid OAuth token: {exc}") from exc
        return Principal(
            email=claims["email"].lower(),
            name="",
            provider="oauth",
            token_id=claims.get("jti", ""),
            expires_at=float(claims.get("exp", 0)),
        )

    # --- CSRF for the login page ----------------------------------------------------

    def csrf_token(self, request: dict[str, str]) -> str:
        """Stateless token bound to this authorization request and a 15-minute window."""
        window = int(time.time()) // CSRF_SECONDS
        return self._csrf_for(request, window)

    def check_csrf(self, request: dict[str, str], token: str) -> bool:
        window = int(time.time()) // CSRF_SECONDS
        return any(
            hmac.compare_digest(self._csrf_for(request, w), token) for w in (window, window - 1)
        )

    def _csrf_for(self, request: dict[str, str], window: int) -> str:
        message = "|".join([request["client_id"], request["redirect_uri"], request["code_challenge"],
                            request["state"], str(window)]).encode()
        return hmac.new(self.settings.jwt_secret.encode(), message, hashlib.sha256).hexdigest()

    def _audit(self, action: str, outcome: str | None, *, actor: str | None = None,
               target: str | None = None, detail: dict[str, Any] | None = None) -> None:
        if self.audit is not None:
            self.audit.record(action, outcome=outcome or "success", actor=actor, target=target, detail=detail)

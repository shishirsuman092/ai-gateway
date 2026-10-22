"""Auth service: picks the provider from config, resolves tokens to user rows, handles local login.

Two bearer token kinds are accepted:
- Databricks PAT (`dapi...`): verified against the workspace; maps to a gateway account by email
  (users) or applicationId (service principals). Works with every AUTH_PROVIDER.
- Provider token: JWT from local login, or Google/Cognito ID or access token.
"""

from __future__ import annotations

from typing import Any

import httpx

import time

from ..audit import AuditLog
from ..config import Settings
from ..users import UserService
from .base import AuthError, TokenVerifier
from .databricks import DatabricksPATVerifier, looks_like_pat
from .local import LocalTokenIssuer, hash_password, verify_password
from .oidc import GOOGLE_ISSUERS, GOOGLE_JWKS_URL, OIDCVerifier

MIN_PASSWORD_LENGTH = 8


def build_verifier(settings: Settings) -> TokenVerifier:
    if settings.auth_provider == "local":
        return LocalTokenIssuer(settings.jwt_secret, settings.jwt_ttl_seconds)
    if settings.auth_provider == "google":
        return OIDCVerifier(
            "google",
            issuers=GOOGLE_ISSUERS,
            jwks_url=GOOGLE_JWKS_URL,
            client_id=settings.google_client_id,
            hosted_domain=settings.google_hosted_domain,
        )
    if settings.auth_provider == "aws":
        issuer = f"https://cognito-idp.{settings.aws_region}.amazonaws.com/{settings.cognito_user_pool_id}"
        return OIDCVerifier(
            "aws",
            issuers=(issuer,),
            jwks_url=f"{issuer}/.well-known/jwks.json",
            client_id=settings.cognito_client_id,
        )
    raise ValueError(f"unknown auth provider {settings.auth_provider!r}")


GENERIC_LOGIN_ERROR = "invalid email or password"  # same message for unknown, locked and wrong-password


class AuthService:
    def __init__(
        self,
        settings: Settings,
        users: UserService,
        *,
        databricks_http: httpx.AsyncClient | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.settings = settings
        self.users = users
        self.audit = audit
        self.db = users.db
        self.verifier = build_verifier(settings)
        self.oauth: Any = None  # set by app: OAuthService verifies tokens it issued
        self.pat: DatabricksPATVerifier | None = None
        if settings.pat_auth_enabled:
            self.pat = DatabricksPATVerifier(
                settings.databricks_host,
                cache_seconds=settings.databricks_pat_cache_seconds,
                http=databricks_http,
            )

    @property
    def provider(self) -> str:
        return self.settings.auth_provider

    async def authenticate(self, token: str) -> dict[str, Any]:
        """Bearer token -> active gateway user row."""
        if looks_like_pat(token):
            user = await self._authenticate_pat(token)
        else:
            user = self._authenticate_provider_token(token)
        if not user["is_active"]:
            raise AuthError("account disabled")
        return user

    def _audit(self, action: str, outcome: str, actor: str | None, **kwargs: Any) -> None:
        if self.audit is not None:
            self.audit.record(action, outcome=outcome, actor=actor, **kwargs)

    def logout(self, token: str) -> None:
        """Revoke a local JWT until its natural expiry. Idempotent."""
        if looks_like_pat(token) or self.provider != "local":
            raise AuthError("logout applies to gateway-issued tokens only")
        principal = self.verifier.verify(token)
        self.db.execute(
            "INSERT OR REPLACE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)",
            (principal.token_id, principal.expires_at),
        )
        self.db.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (time.time(),))
        self._audit("auth.logout", "success", principal.email, target=principal.token_id)

    def _is_revoked(self, token_id: str) -> bool:
        return bool(token_id) and self.db.one("SELECT 1 AS r FROM revoked_tokens WHERE jti = ?", (token_id,)) is not None

    async def _authenticate_pat(self, token: str) -> dict[str, Any]:
        if self.pat is None:
            raise AuthError("Databricks PAT auth is disabled")
        identity = await self.pat.verify(token)
        user = self.users.get(identity.email)
        if user is None:
            # PATs never auto-provision: an admin must create the account and its tool grants first.
            raise AuthError(f"no gateway account for {identity.email}; ask an admin to create it")
        if user["kind"] != identity.kind:
            raise AuthError(f"gateway account {identity.email} is a {user['kind']} account, not {identity.kind}")
        return user

    def _authenticate_provider_token(self, token: str) -> dict[str, Any]:
        oauth_principal = self.oauth.verify_access_token(token) if self.oauth is not None else None
        if oauth_principal is not None:
            if self._is_revoked(oauth_principal.token_id):
                raise AuthError("token has been revoked")
            user = self.users.get(oauth_principal.email)
            if user is None:
                raise AuthError("no gateway account for this OAuth user")
            return user
        principal = self.verifier.verify(token)
        if self._is_revoked(principal.token_id):
            raise AuthError("token has been revoked")
        user = self.users.get(principal.email)
        if user is None:
            if self.provider == "local":
                raise AuthError("unknown user")
            user = self.users.provision_sso(principal.email, principal.name, self.provider)
        return user

    async def register_pat_account(
        self,
        pat: str,
        *,
        role: str = "user",
        tools: list[str] | None = None,
        name: str = "",
    ) -> dict[str, Any]:
        """Create or update the gateway account that owns a Databricks PAT.

        The workspace identifies the owner (user or service principal), so the admin
        only supplies the PAT, role and tools. The PAT itself is not stored.
        """
        if not looks_like_pat(pat or ""):
            raise ValueError("token is not a Databricks PAT (must start with 'dapi')")
        if self.pat is None:
            raise ValueError("Databricks PAT auth is disabled or DATABRICKS_HOST is not set")
        identity = await self.pat.verify(pat)  # raises AuthError if the workspace rejects it
        existing = self.users.get(identity.email)
        if existing is None:
            row = self.users.create(
                identity.email,
                provider="databricks",
                name=name or identity.name,
                role=role,
                tools=tools or [],
                kind=identity.kind,
            )
            action = "created"
        else:
            if existing["kind"] != identity.kind:
                raise ValueError(f"{identity.email} already exists as a {existing['kind']} account")
            row = self.users.update(identity.email, role=role, tools=tools or [], is_active=True)
            action = "updated"
        self._audit("account.from_pat", "success", identity.email,
                    target=identity.email, detail={"action": action, "kind": identity.kind, "role": role})
        return {"action": action, **row}

    def login(self, email: str, password: str) -> dict[str, Any]:
        """Local username/password login. Disabled when an SSO provider is active.

        Failed attempts are counted per account; at LOGIN_MAX_FAILURES the account locks for
        LOGIN_LOCKOUT_SECONDS. Every failure returns the same message, so accounts cannot be enumerated.
        """
        if self.provider != "local":
            raise AuthError("password login is disabled; sign in with SSO")
        email = (email or "").strip().lower()
        row = self.users.get_with_secret(email)
        if row is not None and self.users.is_locked(email):
            self._audit("auth.login", "denied", email, detail={"reason": "locked"})
            raise AuthError(GENERIC_LOGIN_ERROR)
        if row is None or not row["is_active"] or not verify_password(password or "", row["password_hash"]):
            if row is not None:
                locked_now = self.users.record_login_failure(
                    email,
                    max_failures=self.settings.login_max_failures,
                    lockout_seconds=self.settings.login_lockout_seconds,
                )
                self._audit("auth.login", "failure", email, detail={"locked_now": locked_now})
            else:
                self._audit("auth.login", "failure", email, detail={"reason": "unknown_user"})
            raise AuthError(GENERIC_LOGIN_ERROR)
        self.users.clear_login_failures(email)
        self._audit("auth.login", "success", email)
        assert isinstance(self.verifier, LocalTokenIssuer)
        return {
            "access_token": self.verifier.issue(row["email"], row["name"]),
            "token_type": "bearer",
            "expires_in": self.verifier.ttl_seconds,
            "must_change_password": bool(row["must_change_password"]),
        }

    def change_password(self, user: dict[str, Any], old_password: str, new_password: str) -> None:
        if self.provider != "local":
            raise AuthError("password change is managed by the SSO provider")
        if user["kind"] == "service":
            raise AuthError("service accounts have no password")
        if len(new_password or "") < MIN_PASSWORD_LENGTH:
            raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
        row = self.users.get_with_secret(user["email"])
        if row is None or not verify_password(old_password or "", row["password_hash"]):
            raise AuthError("current password is wrong")
        self.users.set_password_hash(user["email"], hash_password(new_password), must_change=False)

"""OIDC provider for SSO: verifies RS256 ID/access tokens from Google or AWS Cognito.

The IdP does the login (Google sign-in or Cognito hosted UI). The client sends the
resulting token as `Authorization: Bearer <token>`. This class only checks it.
"""

from __future__ import annotations

from typing import Iterable

import jwt

from .base import AuthError, Principal

GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"


class OIDCVerifier:
    def __init__(
        self,
        provider: str,
        *,
        issuers: Iterable[str],
        jwks_url: str,
        client_id: str,
        hosted_domain: str = "",
    ) -> None:
        self.provider = provider
        self._issuers = tuple(issuers)
        self._client_id = client_id
        self._hosted_domain = hosted_domain
        self._jwks = jwt.PyJWKClient(jwks_url, cache_keys=True)

    def verify(self, token: str) -> Principal:
        try:
            key = self._jwks.get_signing_key_from_jwt(token).key
            # Audience is checked by hand: ID tokens carry `aud`, Cognito access tokens carry `client_id`.
            claims = jwt.decode(token, key, algorithms=["RS256"], options={"verify_aud": False})
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid token: {exc}") from exc

        if claims.get("iss") not in self._issuers:
            raise AuthError("token issuer not trusted")
        if not self._audience_ok(claims):
            raise AuthError("token audience not trusted")
        if claims.get("exp") is None:
            raise AuthError("token has no expiry")

        email = claims.get("email")
        if not email:
            raise AuthError("token has no email claim")
        if claims.get("email_verified") is False:
            raise AuthError("email not verified")
        if self._hosted_domain and claims.get("hd") != self._hosted_domain:
            raise AuthError("Google account is outside the allowed domain")

        name = claims.get("name") or claims.get("cognito:username") or ""
        return Principal(email=email.lower(), name=name, provider=self.provider)

    def _audience_ok(self, claims: dict) -> bool:
        aud = claims.get("aud")
        if isinstance(aud, str):
            aud = [aud]
        return self._client_id in (aud or []) or claims.get("client_id") == self._client_id

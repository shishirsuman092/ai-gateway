"""Local provider: bcrypt passwords, HS256 JWTs signed by this server."""

from __future__ import annotations

import time
import uuid

import bcrypt
import jwt

from .base import AuthError, Principal

ISSUER = "genie-gateway-local"
AUDIENCE = "genie-gateway"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


class LocalTokenIssuer:
    provider = "local"

    def __init__(self, secret: str, ttl_seconds: int) -> None:
        self._secret = secret
        self._ttl = ttl_seconds

    def issue(self, email: str, name: str) -> str:
        now = int(time.time())
        claims = {
            "sub": email,
            "email": email,
            "name": name,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + self._ttl,
            "jti": uuid.uuid4().hex,
        }
        return jwt.encode(claims, self._secret, algorithm="HS256")

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def verify(self, token: str) -> Principal:
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                issuer=ISSUER,
                audience=AUDIENCE,
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid token: {exc}") from exc
        return Principal(
            email=claims["email"].lower(),
            name=claims.get("name", ""),
            provider="local",
            token_id=claims.get("jti", ""),
            expires_at=float(claims.get("exp", 0)),
        )

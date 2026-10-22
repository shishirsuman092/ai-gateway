"""Shared auth types. Every provider turns a bearer token into a Principal."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol


class AuthError(Exception):
    """Token missing, malformed, expired, or not trusted."""


@dataclass(frozen=True)
class Principal:
    email: str  # for service principals: the applicationId
    name: str
    provider: str
    kind: Literal["human", "service"] = "human"
    token_id: str = ""  # jti, for revocation; empty for PATs and IdP tokens
    expires_at: float = 0.0


class TokenVerifier(Protocol):
    provider: str

    def verify(self, token: str) -> Principal: ...

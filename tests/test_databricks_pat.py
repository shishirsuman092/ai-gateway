"""Databricks PAT auth: user PATs and service-principal PATs, checked against a stubbed SCIM Me endpoint."""

import dataclasses

import httpx
import pytest
from starlette.testclient import TestClient

from genie_gateway.app import create_app
from genie_gateway.auth import AuthError, AuthService
from genie_gateway.auth.databricks import DatabricksPATVerifier, looks_like_pat, principal_from_me
from genie_gateway.db import Database
from genie_gateway.users import UserService

HOST = "https://dbc-demo.cloud.databricks.com"
SP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServicePrincipal"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SP_APP_ID = "11111111-2222-3333-4444-555555555555"

IDENTITIES = {
    "dapi-alice": {"schemas": [USER_SCHEMA], "userName": "Alice@Example.com", "displayName": "Alice", "active": True},
    "dapi-admin": {"schemas": [USER_SCHEMA], "userName": "admin@example.com", "displayName": "Admin", "active": True},
    "dapi-ghost": {"schemas": [USER_SCHEMA], "userName": "ghost@example.com", "active": True},
    "dapi-off": {"schemas": [USER_SCHEMA], "userName": "alice@example.com", "active": False},
    "dapi-ci": {"schemas": [SP_SCHEMA], "applicationId": SP_APP_ID, "displayName": "ci-bot", "active": True},
}


class FakeSCIM:
    """Stands in for https://<workspace>/api/2.0/preview/scim/v2/Me and counts calls."""

    def __init__(self, identities=None):
        self.calls = 0
        self.identities = identities if identities is not None else IDENTITIES

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        assert request.url.path == "/api/2.0/preview/scim/v2/Me"
        token = request.headers["authorization"].removeprefix("Bearer ")
        if token in self.identities:
            return httpx.Response(200, json=self.identities[token])
        return httpx.Response(401, json={"message": "invalid token"})


@pytest.fixture
def scim():
    return FakeSCIM()


@pytest.fixture
def pat_settings(settings):
    return dataclasses.replace(settings, databricks_host=HOST, databricks_pat_cache_seconds=300)


def _auth(settings, scim, clock=None):
    """AuthService with a PAT verifier wired to the fake SCIM endpoint and an in-memory DB."""
    db = Database(":memory:")
    users = UserService(db)
    http = httpx.AsyncClient(transport=httpx.MockTransport(scim))
    auth = AuthService(settings, users, databricks_http=http)
    if clock is not None:
        auth.pat = DatabricksPATVerifier(HOST, cache_seconds=300, http=http, clock=clock)
    return auth, users


def test_pat_prefix_detection():
    assert looks_like_pat("dapi-123")
    assert not looks_like_pat("eyJhbGciOi...")


def test_principal_from_me_handles_user_and_service_principal():
    user = principal_from_me(IDENTITIES["dapi-alice"])
    assert (user.email, user.kind) == ("alice@example.com", "human")
    sp = principal_from_me(IDENTITIES["dapi-ci"])
    assert (sp.email, sp.kind) == (SP_APP_ID, "service")


async def test_user_pat_maps_to_existing_gateway_user(pat_settings, scim):
    auth, users = _auth(pat_settings, scim)
    users.create("alice@example.com", provider="databricks", tools=["genie"])
    row = await auth.authenticate("dapi-alice")
    assert row["email"] == "alice@example.com"
    assert row["tools"] == ["genie"]


async def test_pat_identity_is_cached_then_expires(pat_settings, scim):
    now = [1000.0]
    auth, users = _auth(pat_settings, scim, clock=lambda: now[0])
    users.create("alice@example.com", provider="databricks")
    await auth.authenticate("dapi-alice")
    await auth.authenticate("dapi-alice")
    assert scim.calls == 1  # second request served from cache
    now[0] += 301
    await auth.authenticate("dapi-alice")
    assert scim.calls == 2  # cache expired, identity re-checked


async def test_unknown_or_revoked_pat_rejected(pat_settings, scim):
    auth, users = _auth(pat_settings, scim)
    with pytest.raises(AuthError, match="rejected"):
        await auth.authenticate("dapi-revoked")


async def test_pat_without_gateway_account_is_refused(pat_settings, scim):
    auth, _ = _auth(pat_settings, scim)
    with pytest.raises(AuthError, match="no gateway account for ghost@example.com"):
        await auth.authenticate("dapi-ghost")


async def test_inactive_databricks_account_rejected(pat_settings, scim):
    auth, users = _auth(pat_settings, scim)
    users.create("alice@example.com", provider="databricks")
    with pytest.raises(AuthError, match="inactive"):
        await auth.authenticate("dapi-off")


async def test_disabled_gateway_account_rejected(pat_settings, scim):
    auth, users = _auth(pat_settings, scim)
    users.create("alice@example.com", provider="databricks")
    users.update("alice@example.com", is_active=False)
    with pytest.raises(AuthError, match="disabled"):
        await auth.authenticate("dapi-alice")


async def test_service_pat_maps_to_service_account_by_application_id(pat_settings, scim):
    auth, users = _auth(pat_settings, scim)
    users.create(SP_APP_ID, provider="databricks", kind="service", tools=["genie"])
    row = await auth.authenticate("dapi-ci")
    assert row["kind"] == "service"
    assert row["tools"] == ["genie"]


async def test_user_pat_cannot_claim_service_account(pat_settings, scim):
    auth, users = _auth(pat_settings, scim)
    users.create("alice@example.com", provider="databricks", kind="service")
    with pytest.raises(AuthError, match="not human"):
        await auth.authenticate("dapi-alice")


async def test_pat_auth_disabled_refuses_pats_but_keeps_jwt(settings, scim):
    off = dataclasses.replace(settings, databricks_host=HOST, databricks_pat_auth=False)
    auth, users = _auth(off, scim)
    assert auth.pat is None
    users.create("alice@example.com", provider="databricks")
    with pytest.raises(AuthError, match="disabled"):
        await auth.authenticate("dapi-alice")


def test_service_account_cannot_have_password(settings):
    db = Database(":memory:")
    users = UserService(db)
    with pytest.raises(Exception, match="cannot have a password"):
        users.create(SP_APP_ID, provider="databricks", kind="service", password_hash="x")


def test_http_pat_access_follows_role(pat_settings, scim):
    """Admin PAT reaches admin routes; a user-role PAT and a service PAT do not."""
    http = httpx.AsyncClient(transport=httpx.MockTransport(scim))
    with TestClient(create_app(pat_settings, databricks_http=http)) as client:
        # Seed: admin row comes from ADMIN_EMAIL (admin@example.com). Add Alice and a service account.
        admin = {"Authorization": "Bearer dapi-admin"}
        assert client.get("/admin/users", headers=admin).status_code == 200

        created = client.post("/admin/users", headers=admin,
                              json={"email": "alice@example.com", "role": "user", "tools": ["genie"]})
        assert created.status_code == 201
        assert client.get("/admin/users", headers={"Authorization": "Bearer dapi-alice"}).status_code == 403

        svc = client.post("/admin/users", headers=admin,
                          json={"email": SP_APP_ID, "kind": "service", "role": "user", "tools": ["genie"]})
        assert svc.status_code == 201
        assert svc.json()["kind"] == "service"
        assert client.get("/admin/users", headers={"Authorization": "Bearer dapi-ci"}).status_code == 403


def test_service_account_creation_rejects_password(pat_settings, scim):
    http = httpx.AsyncClient(transport=httpx.MockTransport(scim))
    with TestClient(create_app(pat_settings, databricks_http=http)) as client:
        resp = client.post("/admin/users", headers={"Authorization": "Bearer dapi-admin"},
                           json={"email": SP_APP_ID, "kind": "service", "password": "Longenough1"})
        assert resp.status_code == 400

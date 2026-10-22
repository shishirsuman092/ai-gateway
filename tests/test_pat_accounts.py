"""Simplified PAT onboarding: admin API and CLI register a user or service principal from a PAT alone."""

import dataclasses
import json

import httpx
import pytest
from starlette.testclient import TestClient

import genie_gateway.cli as cli
from genie_gateway.app import create_app
from genie_gateway.cli import add_pat, main as cli_main
from tests.test_databricks_pat import HOST, IDENTITIES, SP_APP_ID, FakeSCIM

PAT_USER = "dapi" + "b" * 32
PAT_SVC = "dapi" + "c" * 32
PAT_REVOKED = "dapi" + "9" * 32  # not in the fake workspace, so the workspace answers 401

SCIM_IDENTITIES = {
    **IDENTITIES,
    PAT_USER: {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
               "userName": "Dana@Example.com", "displayName": "Dana", "active": True},
    PAT_SVC: {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServicePrincipal"],
              "applicationId": SP_APP_ID, "displayName": "ci", "active": True},
}


def _scim():
    return FakeSCIM(SCIM_IDENTITIES)


def _client(settings, scim):
    http = httpx.AsyncClient(transport=httpx.MockTransport(scim))
    return TestClient(create_app(dataclasses.replace(settings, databricks_host=HOST), databricks_http=http))


def _admin_headers(client):
    token = client.post("/auth/login", json={"email": "admin@example.com", "password": "Admin@123"}).json()["access_token"]
    client.post("/auth/change-password", headers={"Authorization": f"Bearer {token}"},
                json={"old_password": "Admin@123", "new_password": "NewAdmin#2026"})
    fresh = client.post("/auth/login", json={"email": "admin@example.com", "password": "NewAdmin#2026"}).json()
    return {"Authorization": f"Bearer {fresh['access_token']}"}


def test_admin_adds_user_pat_with_only_token_and_grants(settings):
    with _client(settings, _scim()) as client:
        h = _admin_headers(client)
        resp = client.post("/admin/accounts/from-pat", headers=h,
                           json={"pat": PAT_USER, "role": "user", "tools": ["genie", "jira"]})
        assert resp.status_code == 201
        body = resp.json()
        assert body["action"] == "created"
        assert body["email"] == "dana@example.com"  # identity comes from Databricks, lower-cased
        assert body["kind"] == "human"
        assert body["tools"] == ["genie", "jira"]


def test_admin_adds_service_principal_pat(settings):
    with _client(settings, _scim()) as client:
        h = _admin_headers(client)
        resp = client.post("/admin/accounts/from-pat", headers=h, json={"pat": PAT_SVC, "tools": ["genie"]})
        assert resp.status_code == 201
        assert resp.json()["email"] == SP_APP_ID
        assert resp.json()["kind"] == "service"


def test_repeat_call_updates_instead_of_failing(settings):
    with _client(settings, _scim()) as client:
        h = _admin_headers(client)
        client.post("/admin/accounts/from-pat", headers=h, json={"pat": PAT_USER, "tools": ["genie"]})
        resp = client.post("/admin/accounts/from-pat", headers=h,
                           json={"pat": PAT_USER, "role": "admin", "tools": ["jira"]})
        assert resp.status_code == 200
        assert resp.json()["action"] == "updated"
        assert resp.json()["role"] == "admin"


def test_rejects_non_pat_and_revoked_pat(settings):
    with _client(settings, _scim()) as client:
        h = _admin_headers(client)
        assert client.post("/admin/accounts/from-pat", headers=h, json={"pat": "not-a-pat"}).status_code == 400
        assert client.post("/admin/accounts/from-pat", headers=h, json={"pat": PAT_REVOKED}).status_code == 400


def test_non_admin_cannot_register_pat(settings):
    with _client(settings, _scim()) as client:
        h = _admin_headers(client)
        client.post("/admin/users", headers=h, json={"email": "eve@example.com", "password": "Eve-pass-123"})
        eve = client.post("/auth/login", json={"email": "eve@example.com", "password": "Eve-pass-123"}).json()
        client.post("/auth/change-password", headers={"Authorization": f"Bearer {eve['access_token']}"},
                    json={"old_password": "Eve-pass-123", "new_password": "Eve-pass-456"})
        eve2 = client.post("/auth/login", json={"email": "eve@example.com", "password": "Eve-pass-456"}).json()
        resp = client.post("/admin/accounts/from-pat", headers={"Authorization": f"Bearer {eve2['access_token']}"},
                           json={"pat": PAT_USER})
        assert resp.status_code == 403


def test_token_never_written_to_audit_log(settings):
    with _client(settings, _scim()) as client:
        h = _admin_headers(client)
        client.post("/admin/accounts/from-pat", headers=h, json={"pat": PAT_USER, "tools": ["genie"]})
        audit = client.get("/admin/audit?action=account.from_pat", headers=h).json()
        assert audit
        assert PAT_USER not in json.dumps(audit)


def test_cli_add_pat_with_env_token(settings, monkeypatch, capsys):
    monkeypatch.setenv("TEST_PAT", PAT_SVC)
    monkeypatch.setattr(cli.Settings, "from_env", classmethod(lambda cls: dataclasses.replace(settings, databricks_host=HOST)))
    http = httpx.AsyncClient(transport=httpx.MockTransport(_scim()))
    real_add = cli.add_pat
    monkeypatch.setattr(cli, "add_pat", lambda s, pat, **kw: real_add(s, pat, databricks_http=http, **kw))

    assert cli_main(["add-pat", "--token-env", "TEST_PAT", "--tools", "genie"]) == 0
    captured = capsys.readouterr().out
    out = json.loads(captured)
    assert out["kind"] == "service" and out["action"] == "created"
    assert PAT_SVC not in captured  # token never printed


def test_cli_rejects_unknown_tool_before_any_call(monkeypatch):
    monkeypatch.setenv("TEST_PAT", PAT_USER)
    with pytest.raises(SystemExit):
        cli_main(["add-pat", "--token-env", "TEST_PAT", "--tools", "sharepoint"])


def test_add_pat_function_direct(settings):
    result = add_pat(
        dataclasses.replace(settings, databricks_host=HOST),
        PAT_USER,
        role="user",
        tools=["jira"],
        databricks_http=httpx.AsyncClient(transport=httpx.MockTransport(_scim())),
    )
    assert result["email"] == "dana@example.com"

"""OAuth 2.1 authorization server (PKCE, DCR, refresh rotation) and HTTPS configuration."""

import base64
import dataclasses
import hashlib
import re
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from starlette.testclient import TestClient

from genie_gateway.app import create_app
from genie_gateway.config import Settings
from genie_gateway.oauth import is_allowed_redirect

BASE = "https://gw.example.com"
REDIRECT = "https://chat.example.com/callback"
VERIFIER = "v" * 64


def _challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


@pytest.fixture
def oauth_settings(settings):
    return dataclasses.replace(settings, public_base_url=BASE)


def _admin_bearer(client):
    """Seeded admin with the forced password change completed. Returns the Authorization header."""
    token = client.post("/auth/login", json={"email": "admin@example.com", "password": "Admin@123"}).json()
    bearer = {"Authorization": f"Bearer {token['access_token']}"}
    client.post("/auth/change-password", headers=bearer,
                json={"old_password": "Admin@123", "new_password": "NewAdmin#2026"})
    return "NewAdmin#2026"


def _register(client):
    resp = client.post("/oauth/register", json={"client_name": "ChatGPT test", "redirect_uris": [REDIRECT]})
    assert resp.status_code == 201
    return resp.json()["client_id"]


def _authorize_params(client_id, state="xyz"):
    return {"client_id": client_id, "redirect_uri": REDIRECT, "response_type": "code",
            "code_challenge": _challenge(VERIFIER), "code_challenge_method": "S256", "state": state}


def _csrf_from(html):
    return re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)


def _approve(client, client_id, password, state="xyz"):
    """Run the login page: GET to get the form and CSRF, then POST credentials. Returns the 302."""
    page = client.get("/oauth/authorize", params=_authorize_params(client_id, state))
    assert page.status_code == 200
    form = {k: v for k, v in _authorize_params(client_id, state).items()}
    form.update({"csrf": _csrf_from(page.text), "email": "admin@example.com", "password": password, "pat": ""})
    return client.post("/oauth/authorize", data=form, follow_redirects=False)


def _exchange(client, client_id, code):
    return client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": client_id,
        "redirect_uri": REDIRECT, "code_verifier": VERIFIER,
    })


# --- discovery -------------------------------------------------------------------

def test_protected_resource_metadata_points_at_mcp_and_issuer(oauth_settings):
    with TestClient(create_app(oauth_settings)) as client:
        meta = client.get("/.well-known/oauth-protected-resource").json()
        assert meta["resource"] == f"{BASE}/mcp"
        assert meta["authorization_servers"] == [BASE]


def test_authorization_server_metadata_advertises_pkce_s256(oauth_settings):
    with TestClient(create_app(oauth_settings)) as client:
        meta = client.get("/.well-known/oauth-authorization-server").json()
        assert meta["issuer"] == BASE
        assert meta["authorization_endpoint"] == f"{BASE}/oauth/authorize"
        assert meta["token_endpoint"] == f"{BASE}/oauth/token"
        assert meta["registration_endpoint"] == f"{BASE}/oauth/register"
        assert meta["code_challenge_methods_supported"] == ["S256"]


def test_mcp_401_carries_resource_metadata_challenge(oauth_settings):
    with TestClient(create_app(oauth_settings)) as client:
        resp = client.post("/mcp", json={})
        assert resp.status_code == 401
        assert resp.headers["www-authenticate"].startswith("Bearer resource_metadata=")
        assert f"{BASE}/.well-known/oauth-protected-resource" in resp.headers["www-authenticate"]


# --- dynamic client registration ---------------------------------------------------

def test_registration_accepts_https_and_loopback_only(oauth_settings):
    with TestClient(create_app(oauth_settings)) as client:
        ok = client.post("/oauth/register", json={"client_name": "x", "redirect_uris": ["http://localhost:9000/cb"]})
        assert ok.status_code == 201
        plain = client.post("/oauth/register", json={"client_name": "x", "redirect_uris": ["http://evil.example/cb"]})
        assert plain.status_code == 400
        assert plain.json()["error"] == "invalid_redirect_uri"
        frag = client.post("/oauth/register", json={"client_name": "x", "redirect_uris": ["https://a.example/cb#f"]})
        assert frag.status_code == 400


def test_redirect_rules():
    assert is_allowed_redirect("https://chat.example.com/cb")
    assert is_allowed_redirect("http://127.0.0.1:5555/cb")
    assert not is_allowed_redirect("http://chat.example.com/cb")
    assert not is_allowed_redirect("javascript:alert(1)")


def test_registration_can_be_disabled(oauth_settings):
    off = dataclasses.replace(oauth_settings, oauth_allow_dynamic_registration=False)
    with TestClient(create_app(off)) as client:
        resp = client.post("/oauth/register", json={"client_name": "x", "redirect_uris": [REDIRECT]})
        assert resp.status_code == 403
        assert "registration_endpoint" not in client.get("/.well-known/oauth-authorization-server").json()


# --- authorization code + PKCE ----------------------------------------------------

def test_full_flow_issues_token_that_opens_mcp_admin_api(oauth_settings):
    with TestClient(create_app(oauth_settings)) as client:
        password = _admin_bearer(client)
        client_id = _register(client)

        approved = _approve(client, client_id, password, state="abc")
        assert approved.status_code == 302
        location = urlparse(approved.headers["location"])
        query = parse_qs(location.query)
        assert location.netloc == "chat.example.com"
        assert query["state"] == ["abc"]

        tokens = _exchange(client, client_id, query["code"][0]).json()
        assert tokens["token_type"] == "Bearer"
        claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
        assert claims["aud"] == f"{BASE}/mcp"
        assert claims["iss"] == BASE

        resp = client.get("/admin/users", headers={"Authorization": f"Bearer {tokens['access_token']}"})
        assert resp.status_code == 200


def test_code_is_single_use(oauth_settings):
    with TestClient(create_app(oauth_settings)) as client:
        password = _admin_bearer(client)
        client_id = _register(client)
        code = parse_qs(urlparse(_approve(client, client_id, password).headers["location"]).query)["code"][0]
        assert _exchange(client, client_id, code).status_code == 200
        replay = _exchange(client, client_id, code)
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"


def test_wrong_pkce_verifier_rejected(oauth_settings):
    with TestClient(create_app(oauth_settings)) as client:
        password = _admin_bearer(client)
        client_id = _register(client)
        code = parse_qs(urlparse(_approve(client, client_id, password).headers["location"]).query)["code"][0]
        bad = client.post("/oauth/token", data={
            "grant_type": "authorization_code", "code": code, "client_id": client_id,
            "redirect_uri": REDIRECT, "code_verifier": "w" * 64})
        assert bad.status_code == 400
        assert bad.json()["error"] == "invalid_grant"


def test_authorize_requires_pkce_and_registered_redirect(oauth_settings):
    with TestClient(create_app(oauth_settings)) as client:
        client_id = _register(client)
        no_pkce = _authorize_params(client_id)
        del no_pkce["code_challenge"]
        assert client.get("/oauth/authorize", params=no_pkce).status_code == 400
        other = dict(_authorize_params(client_id), redirect_uri="https://attacker.example/cb")
        assert client.get("/oauth/authorize", params=other).status_code == 400


def test_bad_csrf_token_rejected(oauth_settings):
    with TestClient(create_app(oauth_settings)) as client:
        password = _admin_bearer(client)
        client_id = _register(client)
        form = dict(_authorize_params(client_id), csrf="0" * 64, email="admin@example.com", password=password, pat="")
        resp = client.post("/oauth/authorize", data=form, follow_redirects=False)
        assert resp.status_code == 400


def test_wrong_password_on_login_page_shows_error_not_code(oauth_settings):
    with TestClient(create_app(oauth_settings)) as client:
        _admin_bearer(client)
        client_id = _register(client)
        resp = _approve(client, client_id, "wrong-password")
        assert resp.status_code == 401
        assert "location" not in resp.headers
        assert "invalid email or password" in resp.text


def test_refresh_token_rotates_and_old_one_is_refused(oauth_settings):
    with TestClient(create_app(oauth_settings)) as client:
        password = _admin_bearer(client)
        client_id = _register(client)
        code = parse_qs(urlparse(_approve(client, client_id, password).headers["location"]).query)["code"][0]
        first = _exchange(client, client_id, code).json()

        second = client.post("/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": first["refresh_token"], "client_id": client_id}).json()
        assert second["access_token"]
        assert second["refresh_token"] != first["refresh_token"]

        replay = client.post("/oauth/token", data={
            "grant_type": "refresh_token", "refresh_token": first["refresh_token"], "client_id": client_id})
        assert replay.status_code == 400


def test_token_signed_with_other_audience_is_refused(oauth_settings):
    with TestClient(create_app(oauth_settings)) as client:
        now = int(time.time())
        forged = jwt.encode({
            "iss": BASE, "aud": "https://other.example/mcp", "sub": "admin@example.com",
            "email": "admin@example.com", "iat": now, "exp": now + 600, "jti": "x1",
        }, oauth_settings.jwt_secret, algorithm="HS256")
        resp = client.get("/admin/users", headers={"Authorization": f"Bearer {forged}"})
        assert resp.status_code == 401


def test_unknown_grant_type(oauth_settings):
    with TestClient(create_app(oauth_settings)) as client:
        resp = client.post("/oauth/token", data={"grant_type": "password"})
        assert resp.json()["error"] == "unsupported_grant_type"


def test_login_page_sets_security_headers(oauth_settings):
    with TestClient(create_app(oauth_settings)) as client:
        client_id = _register(client)
        page = client.get("/oauth/authorize", params=_authorize_params(client_id))
        assert "default-src 'none'" in page.headers["content-security-policy"]
        assert page.headers["x-frame-options"] == "DENY"


# --- HTTPS configuration ----------------------------------------------------------

def test_hsts_sent_only_when_public_url_is_https(oauth_settings, settings):
    with TestClient(create_app(oauth_settings)) as client:
        assert "max-age" in client.get("/health").headers["strict-transport-security"]
    with TestClient(create_app(settings)) as client:
        assert "strict-transport-security" not in client.get("/health").headers


def test_base_url_defaults_to_local_listener(settings):
    assert settings.base_url == "http://127.0.0.1:8000"
    with_tls = dataclasses.replace(settings, tls_cert_file="c.pem", tls_key_file="k.pem")
    assert with_tls.base_url == "https://127.0.0.1:8000"


def test_tls_files_must_come_as_a_pair(settings):
    with pytest.raises(ValueError, match="set together"):
        dataclasses.replace(settings, tls_cert_file="c.pem")


def test_public_url_needs_scheme(settings):
    with pytest.raises(ValueError, match="PUBLIC_BASE_URL"):
        dataclasses.replace(settings, public_base_url="gw.example.com")


def test_production_requires_https_and_a_termination_story(settings):
    base = dict(app_env="production", jwt_secret="x" * 40, auth_provider="google", google_client_id="c",
                db_path=":memory:")
    with pytest.raises(ValueError, match="https"):
        Settings(**base, public_base_url="http://gw.example.com", trusted_proxy_ips="10.0.0.1")
    with pytest.raises(ValueError, match="TRUSTED_PROXY_IPS"):
        Settings(**base, public_base_url="https://gw.example.com")
    Settings(**base, public_base_url="https://gw.example.com", tls_cert_file="c.pem", tls_key_file="k.pem")
    Settings(**base, public_base_url="https://gw.example.com", trusted_proxy_ips="10.0.0.1")


def test_mcp_accepts_public_host_behind_tunnel_or_proxy(oauth_settings):
    """Regression: DNS-rebinding guard must allow the public host, not only localhost."""
    with TestClient(create_app(oauth_settings)) as client:
        bearer = {"Authorization": f"Bearer {_admin_bearer_token(client)}"}
        resp = client.post("/mcp", headers={**bearer, "Host": "gw.example.com",
                                            "Accept": "application/json, text/event-stream"},
                           json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                 "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                            "clientInfo": {"name": "t", "version": "1"}}})
        assert resp.status_code == 200
        assert resp.json()["result"]["serverInfo"]["name"] == "genie-gateway"


def _admin_bearer_token(client):
    token = client.post("/auth/login", json={"email": "admin@example.com", "password": "Admin@123"}).json()
    bearer = {"Authorization": f"Bearer {token['access_token']}"}
    client.post("/auth/change-password", headers=bearer,
                json={"old_password": "Admin@123", "new_password": "NewAdmin#2026"})
    return client.post("/auth/login", json={"email": "admin@example.com", "password": "NewAdmin#2026"}).json()["access_token"]


def test_login_form_round_trip_submits_all_authorization_fields(oauth_settings):
    """Regression: the browser posts back the form's hidden fields. They must include response_type."""
    with TestClient(create_app(oauth_settings)) as client:
        password = _admin_bearer(client)
        client_id = _register(client)
        page = client.get("/oauth/authorize", params=_authorize_params(client_id, "rt1"))
        hidden = dict(re.findall(r'<input type="hidden" name="([a-z_]+)" value="([^"]*)">', page.text))
        assert hidden["response_type"] == "code"
        assert hidden["code_challenge_method"] == "S256"
        form = dict(hidden, email="admin@example.com", password=password, pat="")
        resp = client.post("/oauth/authorize", data=form, follow_redirects=False)
        assert resp.status_code == 302, resp.text[:200]


def test_login_page_changes_required_password_inline(oauth_settings):
    """Regression: a user with must_change_password can finish sign-in on the login page."""
    with TestClient(create_app(oauth_settings)) as client:
        client_id = _register(client)  # admin is still at the default, must-change password
        page = client.get("/oauth/authorize", params=_authorize_params(client_id))
        hidden = dict(re.findall(r'<input type="hidden" name="([a-z_]+)" value="([^"]*)">', page.text))
        form = dict(hidden, csrf=_csrf_from(page.text), email="admin@example.com", password="Admin@123",
                    pat="", new_password="")
        refused = client.post("/oauth/authorize", data=form, follow_redirects=False)
        assert refused.status_code == 401
        assert "requires a new password" in refused.text
        form["new_password"] = "Brand-New-2026"
        form["csrf"] = _csrf_from(client.get("/oauth/authorize", params=_authorize_params(client_id)).text)
        ok = client.post("/oauth/authorize", data=form, follow_redirects=False)
        assert ok.status_code == 302

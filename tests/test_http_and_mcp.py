"""HTTP auth/admin routes, plus a real MCP client round trip against a running server."""

import asyncio
import json
import socket

import httpx
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from starlette.testclient import TestClient

from genie_gateway.app import create_app


def _login(client, email="admin@example.com", password="Admin@123"):
    return client.post("/auth/login", json={"email": email, "password": password})


def test_health_is_public(settings):
    with TestClient(create_app(settings)) as client:
        assert client.get("/health").json()["ok"] is True


def test_mcp_requires_bearer_token(settings):
    with TestClient(create_app(settings)) as client:
        assert client.post("/mcp", json={}).status_code == 401
        assert client.post("/mcp", json={}, headers={"Authorization": "Bearer nonsense"}).status_code == 401


def test_default_admin_must_change_password_before_gateway_use(settings):
    with TestClient(create_app(settings)) as client:
        token = _login(client).json()
        assert token["must_change_password"] is True
        headers = {"Authorization": f"Bearer {token['access_token']}"}
        blocked = client.post("/mcp", json={}, headers=headers)
        assert blocked.status_code == 403
        assert client.post("/auth/change-password", headers=headers,
                           json={"old_password": "Admin@123", "new_password": "NewAdmin#2026"}).status_code == 200
        assert _login(client, password="NewAdmin#2026").json()["must_change_password"] is False


def test_admin_creates_user_and_non_admin_is_refused(settings):
    with TestClient(create_app(settings)) as client:
        admin_token = _login(client).json()["access_token"]
        client.post("/auth/change-password", headers={"Authorization": f"Bearer {admin_token}"},
                    json={"old_password": "Admin@123", "new_password": "NewAdmin#2026"})
        admin_token = _login(client, password="NewAdmin#2026").json()["access_token"]
        admin = {"Authorization": f"Bearer {admin_token}"}

        created = client.post("/admin/users", headers=admin, json={
            "email": "alice@example.com", "password": "Alice-pass-1", "role": "user", "tools": ["genie"]})
        assert created.status_code == 201
        assert created.json()["tools"] == ["genie"]

        alice_token = _login(client, "alice@example.com", "Alice-pass-1").json()
        assert alice_token["must_change_password"] is True  # admin-set passwords must be changed
        alice = {"Authorization": f"Bearer {alice_token['access_token']}"}
        client.post("/auth/change-password", headers=alice,
                    json={"old_password": "Alice-pass-1", "new_password": "Alice-pass-2"})
        alice = {"Authorization": f"Bearer {_login(client, 'alice@example.com', 'Alice-pass-2').json()['access_token']}"}
        assert client.get("/admin/users", headers=alice).status_code == 403
        assert client.post("/admin/users", headers=alice, json={"email": "x@example.com"}).status_code == 403

        # Admin upgrades Alice and grants Jira; the change applies on her next request.
        patched = client.patch("/admin/users/alice@example.com", headers=admin,
                               json={"role": "admin", "tools": ["genie", "jira"]})
        assert patched.status_code == 200
        assert client.get("/admin/users", headers=alice).status_code == 200


def test_sso_mode_hides_password_login(settings):
    from genie_gateway.config import Settings

    sso = Settings(auth_provider="google", google_client_id="client-1",
                   db_path=settings.db_path, admin_email="admin@example.com")
    with TestClient(create_app(sso)) as client:
        assert _login(client).status_code == 404


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_mcp_client_submit_and_poll_async(settings):
    """End to end: real server on a socket, real MCP client, async submit then poll."""
    app = create_app(settings)
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    serve = asyncio.create_task(server.serve())
    try:
        while not server.started:
            await asyncio.sleep(0.05)
        base = f"http://127.0.0.1:{port}"

        async with httpx.AsyncClient() as http:
            token = (await http.post(f"{base}/auth/login",
                                     json={"email": "admin@example.com", "password": "Admin@123"})).json()
            bearer = {"Authorization": f"Bearer {token['access_token']}"}
            await http.post(f"{base}/auth/change-password", headers=bearer,
                            json={"old_password": "Admin@123", "new_password": "NewAdmin#2026"})
            token = (await http.post(f"{base}/auth/login",
                                     json={"email": "admin@example.com", "password": "NewAdmin#2026"})).json()

        headers = {"Authorization": f"Bearer {token['access_token']}"}
        async with streamablehttp_client(f"{base}/mcp", headers=headers) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = {t.name for t in (await session.list_tools()).tools}
                assert {"submit_query", "get_query_result", "list_my_queries"} <= tools

                submitted = await session.call_tool("submit_query", {"question": "Top products by revenue?"})
                job = json.loads(submitted.content[0].text)
                assert job["status"] in ("QUEUED", "RUNNING", "COMPLETED")

                result = await session.call_tool(
                    "get_query_result", {"job_id": job["job_id"], "wait_seconds": 10})
                done = json.loads(result.content[0].text)
                assert done["status"] == "COMPLETED"
                assert "Top products by revenue?" in done["result"]["answer"]
    finally:
        server.should_exit = True
        await serve

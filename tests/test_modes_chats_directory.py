"""Auth modes (service principal vs user PAT), chat history, context summarization, directory sync."""

import dataclasses
import json

import httpx
import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from genie_gateway.app import Services, create_app
from genie_gateway.config import Settings
from genie_gateway.databricks_auth import ServicePrincipalAuth
from genie_gateway.directory import DatabricksDirectory
from genie_gateway.jobs import COMPLETED, JobError
from genie_gateway.tools.genie import GenieAdapter

HOST = "https://dbc-demo.cloud.databricks.com"
KEY = Fernet.generate_key().decode()
SP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServicePrincipal"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"


class FakeDatabricks:
    """Fake workspace: OAuth token endpoint, Genie conversation API, SCIM directory, summarizer APIs."""

    def __init__(self, users=None, service_principals=None, page_size=100):
        self.requests: list[httpx.Request] = []
        self.token_calls = 0
        self.genie_bodies: list[dict] = []
        self.genie_auth: list[str] = []
        self.users = users or []
        self.sps = service_principals or []
        self.page_size = page_size
        self.llm_fail = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/oidc/v1/token":
            self.token_calls += 1
            return httpx.Response(200, json={"access_token": f"sp-token-{self.token_calls}", "expires_in": 3600})
        if path == "/api/2.0/genie/spaces/s1/start-conversation":
            self.genie_auth.append(request.headers["authorization"])
            self.genie_bodies.append(json.loads(request.content))
            return httpx.Response(200, json={"conversation_id": "c1", "message_id": "m1"})
        if path == "/api/2.0/genie/spaces/s1/conversations/c1/messages":
            self.genie_auth.append(request.headers["authorization"])
            self.genie_bodies.append(json.loads(request.content))
            return httpx.Response(200, json={"message_id": "m2"})
        if "/messages/" in path:
            mid = path.rsplit("/", 1)[-1]
            return httpx.Response(200, json={
                "status": "COMPLETED",
                "attachments": [{"text": {"content": f"answer {mid}"}}],
            })
        if path == "/api/2.0/preview/scim/v2/Users":
            return self._scim(request, self.users)
        if path == "/api/2.0/preview/scim/v2/ServicePrincipals":
            return self._scim(request, self.sps)
        if path == "/v1/chat/completions":
            if self.llm_fail:
                return httpx.Response(500, json={"error": "down"})
            return httpx.Response(200, json={"choices": [{"message": {"content": "SUMMARY: bob asked about sales"}}]})
        return httpx.Response(404, json={"message": f"no fake for {path}"})

    def _scim(self, request, items):
        start = int(request.url.params.get("startIndex", "1"))
        count = min(int(request.url.params.get("count", "100")), self.page_size)
        page = items[start - 1:start - 1 + count]
        return httpx.Response(200, json={
            "Resources": page, "totalResults": len(items), "startIndex": start, "itemsPerPage": len(page),
        })


def _sp_settings(settings, **overrides):
    base = dict(databricks_host=HOST, genie_space_id="s1", databricks_client_id="cid",
                databricks_client_secret="secret", genie_poll_seconds=0.01)
    base.update(overrides)
    return dataclasses.replace(settings, **base)


def _services(settings, fake: FakeDatabricks) -> Services:
    http = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    services = Services(settings, databricks_http=http)
    # Point the Genie adapter at the fake workspace (the registry builds its own client otherwise).
    services.registry._adapters["genie"] = GenieAdapter(
        settings,
        http=httpx.AsyncClient(base_url=settings.databricks_host, transport=httpx.MockTransport(fake)),
        credentials=ServicePrincipalAuth(settings.databricks_host, client_id=settings.databricks_client_id,
                                         client_secret=settings.databricks_client_secret,
                                         http=httpx.AsyncClient(transport=httpx.MockTransport(fake))),
    )
    services.jobs.registry = services.registry
    return services


def _user(services, email="alice@example.com", tools=("genie",)):
    return services.users.create(email, provider="databricks", tools=list(tools))


# --- config switch ------------------------------------------------------------------

def test_user_pat_mode_requires_encryption_key(settings):
    with pytest.raises(ValueError, match="GATEWAY_ENCRYPTION_KEY"):
        dataclasses.replace(settings, databricks_auth_mode="user_pat")


def test_user_pat_mode_rejects_bad_key(settings):
    with pytest.raises(ValueError, match="valid Fernet key"):
        dataclasses.replace(settings, databricks_auth_mode="user_pat", gateway_encryption_key="not-a-key")


def test_service_principal_mode_needs_credentials_when_genie_configured(settings):
    with pytest.raises(ValueError, match="DATABRICKS_CLIENT_ID"):
        dataclasses.replace(settings, databricks_host=HOST, genie_space_id="s1")


def test_mode_must_be_known(settings):
    with pytest.raises(ValueError, match="DATABRICKS_AUTH_MODE"):
        dataclasses.replace(settings, databricks_auth_mode="both")


def test_summarizer_provider_needs_key_and_model(settings):
    with pytest.raises(ValueError, match="SUMMARIZER_API_KEY"):
        dataclasses.replace(settings, summarizer_provider="openai")


def test_genie_live_follows_mode(settings):
    assert not _sp_settings(settings, databricks_host="").genie_live
    assert _sp_settings(settings).genie_live
    user = dataclasses.replace(settings, databricks_host=HOST, genie_space_id="s1",
                               databricks_auth_mode="user_pat", gateway_encryption_key=KEY)
    assert user.genie_live  # no service credential needed in user_pat mode


# --- service principal OAuth ----------------------------------------------------------

async def test_service_principal_oauth_token_cached_and_used(settings):
    fake = FakeDatabricks()
    s = _services(_sp_settings(settings), fake)
    alice = _user(s)
    for q in ("first question", "second question"):
        job = s.jobs.submit(alice, q)
        assert (await s.jobs.wait(alice, job["job_id"], timeout=5))["status"] == COMPLETED
    assert fake.token_calls == 1  # token fetched once, reused
    assert set(fake.genie_auth) == {"Bearer sp-token-1"}


# --- user PAT mode --------------------------------------------------------------------

async def test_user_pat_mode_runs_genie_as_caller_and_erases_pat(settings):
    fake = FakeDatabricks()
    pat_settings = dataclasses.replace(
        settings, databricks_host=HOST, genie_space_id="s1", databricks_auth_mode="user_pat",
        gateway_encryption_key=KEY, genie_poll_seconds=0.01)
    s = _services(pat_settings, fake)
    alice = _user(s)
    pat = "dapi" + "b" * 32
    job = s.jobs.submit(alice, "sales by region", user_token=pat)
    done = await s.jobs.wait(alice, job["job_id"], timeout=5)
    assert done["status"] == COMPLETED
    assert fake.genie_auth[0] == f"Bearer {pat}"
    assert fake.token_calls == 0  # gateway identity not used for user_pat
    stored = s.db.one("SELECT user_token_enc FROM jobs WHERE id = ?", (job["job_id"],))
    assert stored["user_token_enc"] is None  # erased after use


async def test_user_pat_mode_refuses_genie_without_pat(settings):
    pat_settings = dataclasses.replace(
        settings, databricks_host=HOST, genie_space_id="s1", databricks_auth_mode="user_pat",
        gateway_encryption_key=KEY)
    s = _services(pat_settings, FakeDatabricks())
    with pytest.raises(JobError, match="sign in with a Databricks PAT"):
        s.jobs.submit(_user(s), "anything")


def test_pat_is_encrypted_at_rest_while_queued(settings):
    from genie_gateway.databricks_auth import decrypt_token, encrypt_token

    token = "dapi" + "c" * 32
    cipher = encrypt_token(KEY, token)
    assert token not in cipher
    assert decrypt_token(KEY, cipher) == token


# --- chat history ---------------------------------------------------------------------

async def test_chat_history_records_messages_and_reuses_genie_conversation(settings):
    fake = FakeDatabricks()
    s = _services(_sp_settings(settings), fake)
    alice = _user(s)

    first = s.jobs.submit(alice, "total sales last month?")
    await s.jobs.wait(alice, first["job_id"], timeout=5)
    chat_id = first["conversation_id"]
    assert chat_id

    second = s.jobs.submit(alice, "and by region?", conversation_id=chat_id)
    await s.jobs.wait(alice, second["job_id"], timeout=5)
    assert second["conversation_id"] == chat_id
    # Follow-up goes to the same Genie conversation, not a new one.
    assert any(r.url.path.endswith("/conversations/c1/messages") for r in fake.requests)

    history = s.chats.messages(alice, chat_id)
    roles = [m["role"] for m in history["messages"]]
    assert roles == ["user", "assistant", "user", "assistant"]
    assert history["messages"][0]["content"] == "total sales last month?"


async def test_chat_history_is_private(settings):
    s = _services(_sp_settings(settings), FakeDatabricks())
    alice, bob = _user(s), _user(s, "bob@example.com")
    job = s.jobs.submit(alice, "hello")
    from genie_gateway.chats import ChatNotFound

    with pytest.raises(ChatNotFound):
        s.chats.messages(bob, job["conversation_id"])
    assert s.chats.list_for(bob) == []
    assert len(s.chats.list_for(alice)) == 1


async def test_chat_history_stores_redacted_question(settings):
    s = _services(_sp_settings(settings), FakeDatabricks())
    alice = _user(s)
    job = s.jobs.submit(alice, "email me at bob@corp.example the totals")
    msgs = s.chats.messages(alice, job["conversation_id"])["messages"]
    assert "bob@corp.example" not in msgs[0]["content"]


# --- context summarization ------------------------------------------------------------

async def test_chat_context_truncated_without_summarizer(settings):
    fake = FakeDatabricks()
    small = _sp_settings(settings, summarizer_max_chars=50)
    s = _services(small, fake)
    alice = _user(s)
    long_context = "old line about revenue. " * 20 + "latest: north region"
    job = s.jobs.submit(alice, "what changed?", chat_context=long_context)
    await s.jobs.wait(alice, job["job_id"], timeout=5)
    sent = fake.genie_bodies[0]["content"]
    assert sent.startswith("Conversation context:")
    assert "[earlier context truncated]" in sent
    assert "latest: north region" in sent
    assert "what changed?" in sent


async def test_chat_context_summarized_by_llm_before_genie(settings):
    fake = FakeDatabricks()
    llm = dataclasses.replace(_sp_settings(settings), summarizer_provider="openai",
                              summarizer_api_key="sk-test", summarizer_model="gpt-test")
    s = _services(llm, fake)
    # Route the summarizer's HTTP calls to the fake too.
    from genie_gateway.summarizer import Summarizer

    s.summarizer = Summarizer(llm, http=httpx.AsyncClient(transport=httpx.MockTransport(fake)))
    s.jobs.summarizer = s.summarizer
    alice = _user(s)
    job = s.jobs.submit(alice, "and now?", chat_context="user: sales for bob@corp.example in May\nassistant: 42")
    await s.jobs.wait(alice, job["job_id"], timeout=5)
    sent = fake.genie_bodies[0]["content"]
    assert "SUMMARY: bob asked about sales" in sent
    assert "42" not in sent  # raw chat is not forwarded
    assert "bob@corp.example" not in sent
    history = s.chats.messages(alice, job["conversation_id"])["messages"]
    assert any(m["role"] == "summary" for m in history)


async def test_summarizer_failure_falls_back_to_truncation(settings):
    fake = FakeDatabricks()
    fake.llm_fail = True
    llm = dataclasses.replace(_sp_settings(settings), summarizer_provider="openai",
                              summarizer_api_key="sk-test", summarizer_model="gpt-test")
    s = _services(llm, fake)
    from genie_gateway.summarizer import Summarizer

    s.summarizer = Summarizer(llm, http=httpx.AsyncClient(transport=httpx.MockTransport(fake)))
    s.jobs.summarizer = s.summarizer
    alice = _user(s)
    job = s.jobs.submit(alice, "follow up", chat_context="earlier discussion about EMEA margins")
    done = await s.jobs.wait(alice, job["job_id"], timeout=5)
    assert done["status"] == COMPLETED
    assert "EMEA margins" in fake.genie_bodies[0]["content"]


async def test_precomputed_summary_skips_summarizer(settings):
    fake = FakeDatabricks()
    s = _services(_sp_settings(settings), fake)
    alice = _user(s)
    job = s.jobs.submit(alice, "next?", context_summary="Client asked about Q3 churn.")
    await s.jobs.wait(alice, job["job_id"], timeout=5)
    assert "Client asked about Q3 churn." in fake.genie_bodies[0]["content"]


# --- directory fetch and sync -----------------------------------------------------------

def _users(n):
    return [{"schemas": [USER_SCHEMA], "userName": f"user{i}@corp.example", "displayName": f"User {i}",
             "active": i != 3} for i in range(n)]


async def test_directory_fetches_all_pages(settings):
    fake = FakeDatabricks(users=_users(250), page_size=100)
    http = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    creds = ServicePrincipalAuth(HOST, static_token="t", http=http)
    entries = await DatabricksDirectory(_sp_settings(settings), creds, http=http).list_users()
    assert len(entries) == 250
    assert entries[0].email == "user0@corp.example"
    assert any(not e.active for e in entries)  # inactive accounts are reported, not dropped


async def test_directory_includes_service_principals(settings):
    app_id = "11111111-2222-3333-4444-555555555555"
    fake = FakeDatabricks(service_principals=[
        {"schemas": [SP_SCHEMA], "applicationId": app_id, "displayName": "ci", "active": True}])
    http = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    creds = ServicePrincipalAuth(HOST, static_token="t", http=http)
    entries = await DatabricksDirectory(_sp_settings(settings), creds, http=http).list_all()
    assert [(e.email, e.kind) for e in entries] == [(app_id, "service")]


def test_sync_endpoint_creates_missing_accounts_once(settings, tmp_path):
    fake = FakeDatabricks(users=_users(5), service_principals=[
        {"schemas": [SP_SCHEMA], "applicationId": "aaaa-bbbb", "displayName": "bot", "active": True}])
    http = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    cfg = _sp_settings(dataclasses.replace(settings, db_path=str(tmp_path / "sync.db")))
    with TestClient(create_app(cfg, databricks_http=http)) as client:
        admin = _admin_header(client)
        dry = client.post("/admin/databricks/directory/sync", headers=admin,
                          json={"dry_run": True, "tools": ["genie"]}).json()
        assert dry["dry_run"] is True and len(dry["created"]) == 5  # 4 active users + 1 service principal
        assert client.get("/admin/users", headers=admin).json().__len__() == 1  # only the admin so far

        run = client.post("/admin/databricks/directory/sync", headers=admin, json={"tools": ["genie"]}).json()
        assert len(run["created"]) == 5  # user3 is inactive and skipped
        assert run["skipped_inactive"] == ["user3@corp.example"]
        assert any(c["kind"] == "service" for c in run["created"])

        again = client.post("/admin/databricks/directory/sync", headers=admin, json={}).json()
        assert again["created"] == [] and again["existing"] == 5
        users = {u["email"]: u for u in client.get("/admin/users", headers=admin).json()}
        assert users["user0@corp.example"]["tools"] == ["genie"]
        assert users["aaaa-bbbb"]["kind"] == "service"


def test_directory_list_endpoint_is_admin_only(settings, tmp_path):
    fake = FakeDatabricks(users=_users(2))
    http = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    cfg = _sp_settings(dataclasses.replace(settings, db_path=str(tmp_path / "dir.db")))
    with TestClient(create_app(cfg, databricks_http=http)) as client:
        assert client.get("/admin/databricks/directory").status_code == 401
        listing = client.get("/admin/databricks/directory", headers=_admin_header(client)).json()
        assert listing["count"] == 2
        assert listing["scope"] == "workspace"


def _admin_header(client):
    """Seeded admin, past the forced password change."""
    token = client.post("/auth/login", json={"email": "admin@example.com", "password": "Admin@123"}).json()
    bearer = {"Authorization": f"Bearer {token['access_token']}"}
    client.post("/auth/change-password", headers=bearer,
                json={"old_password": "Admin@123", "new_password": "NewAdmin#2026"})
    fresh = client.post("/auth/login", json={"email": "admin@example.com", "password": "NewAdmin#2026"}).json()
    return {"Authorization": f"Bearer {fresh['access_token']}"}

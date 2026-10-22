import asyncio

import pytest

from genie_gateway.app import Services
from genie_gateway.jobs import COMPLETED, FAILED, JobNotFound
from genie_gateway.rbac import Forbidden
from genie_gateway.tools import ToolRegistry
from genie_gateway.tools.genie import GenieAdapter
from genie_gateway.users import UserError


class BoomAdapter:
    name = "boom"

    async def run(self, question, *, user, **options):
        raise RuntimeError("warehouse offline")


def _services(settings, *, failing=False) -> Services:
    services = Services(settings)
    if failing:
        services.registry = ToolRegistry({"genie": BoomAdapter(), "slack": BoomAdapter(), "jira": BoomAdapter()})
        services.jobs.registry = services.registry
    return services


def _admin(services):
    return services.users.get("admin@example.com")


def _user(services, email="alice@example.com", tools=("genie",)):
    return services.users.create(email, provider="local", tools=list(tools))


async def test_submit_returns_job_id_then_completes(settings):
    s = _services(settings)
    alice = _user(s)
    job = s.jobs.submit(alice, "How many orders last week?")
    assert job["status"] in ("QUEUED", "RUNNING", COMPLETED)
    done = await s.jobs.wait(alice, job["job_id"], timeout=5)
    assert done["status"] == COMPLETED
    assert done["tool"] == "genie"
    assert done["result"]["mode"] == "mock"
    assert "How many orders last week?" in done["result"]["answer"]


async def test_failed_adapter_marks_job_failed_not_crash(settings):
    s = _services(settings, failing=True)
    alice = _user(s)
    job = s.jobs.submit(alice, "anything")
    done = await s.jobs.wait(alice, job["job_id"], timeout=5)
    assert done["status"] == FAILED
    assert "warehouse offline" in done["error"]


async def test_user_without_grant_cannot_submit_tool(settings):
    s = _services(settings)
    bob = _user(s, "bob@example.com", tools=())
    with pytest.raises(Forbidden):
        s.jobs.submit(bob, "hello")
    with pytest.raises(Forbidden):
        s.jobs.submit(bob, "slack: find deploy notes")


async def test_admin_can_use_any_tool_without_grants(settings):
    s = _services(settings)
    job = s.jobs.submit(_admin(s), "jira: open bugs")
    assert job["tool"] == "jira"


async def test_jobs_are_private_to_owner_unless_admin(settings):
    s = _services(settings)
    alice = _user(s)
    carol = _user(s, "carol@example.com")
    job = s.jobs.submit(alice, "hi")
    with pytest.raises(JobNotFound):
        s.jobs.get(carol, job["job_id"])
    assert s.jobs.get(_admin(s), job["job_id"])["job_id"] == job["job_id"]
    with pytest.raises(JobNotFound):
        s.jobs.get(carol, "does-not-exist")


async def test_empty_question_rejected(settings):
    from genie_gateway.jobs import JobError

    s = _services(settings)
    with pytest.raises(JobError):
        s.jobs.submit(_user(s), "   ")


async def test_recover_marks_unfinished_jobs_failed(settings):
    s = _services(settings)
    alice = _user(s)
    s.db.execute(
        "INSERT INTO jobs (id, user_email, tool, question, status, created_at, updated_at) "
        "VALUES ('old', ?, 'genie', 'q', 'RUNNING', 0, 0)",
        (alice["email"],),
    )
    assert s.jobs.recover() == 1
    assert s.jobs.get(alice, "old")["status"] == FAILED


def test_router_prefixes_and_keywords(settings):
    reg = ToolRegistry.from_settings(settings)
    assert reg.route("how many sales?").tool == "genie"
    assert reg.route("jira: open bugs").question == "open bugs"
    assert reg.route("slack: deploy notes").tool == "slack"
    assert reg.route("create a jira ticket for login bug").tool == "jira"
    assert reg.route("jql: project = X").question == "jql: project = X"
    assert reg.route("anything", tool="slack").tool == "slack"


def test_seed_admin_is_idempotent_and_flags_password_change(settings):
    s = _services(settings)
    admin = s.users.get_with_secret("admin@example.com")
    assert admin["role"] == "admin"
    assert admin["must_change_password"] == 1
    s.users.seed_admin("admin@example.com", provider="local", password_hash="x")
    assert s.users.count_admins() == 1


def test_cannot_demote_or_disable_last_admin(settings):
    s = _services(settings)
    with pytest.raises(UserError):
        s.users.update("admin@example.com", role="user")
    with pytest.raises(UserError):
        s.users.update("admin@example.com", is_active=False)


def test_unknown_tool_grant_rejected(settings):
    s = _services(settings)
    with pytest.raises(UserError):
        s.users.create("dan@example.com", provider="local", tools=["sharepoint"])


async def test_wait_respects_timeout(settings):
    s = _services(settings)
    alice = _user(s)
    # Job stays QUEUED because nothing runs it: insert directly.
    s.db.execute(
        "INSERT INTO jobs (id, user_email, tool, question, status, created_at, updated_at) "
        "VALUES ('slow', ?, 'genie', 'q', 'QUEUED', 0, 0)",
        (alice["email"],),
    )
    start = asyncio.get_running_loop().time()
    job = await s.jobs.wait(alice, "slow", timeout=0.3)
    assert job["status"] == "QUEUED"
    assert asyncio.get_running_loop().time() - start < 2


def test_genie_live_flag_follows_settings(settings):
    assert GenieAdapter(settings).live is False

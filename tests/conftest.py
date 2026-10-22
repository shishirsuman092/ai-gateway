import pytest

from genie_gateway.config import Settings


@pytest.fixture
def settings(tmp_path) -> Settings:
    """Local provider, mock Genie/Slack/Jira, fast polling, temp database."""
    return Settings(
        auth_provider="local",
        jwt_secret="test-secret",
        admin_email="admin@example.com",
        admin_default_password="Admin@123",
        db_path=str(tmp_path / "gateway.db"),
        genie_poll_seconds=0.01,
    )

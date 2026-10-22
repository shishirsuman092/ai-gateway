"""Settings loaded from environment variables. Secrets never live in code."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.fernet import Fernet

VALID_PROVIDERS = ("local", "google", "aws")
DATABRICKS_AUTH_MODES = ("service_principal", "user_pat")
SUMMARIZER_PROVIDERS = ("none", "openai", "anthropic")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


@dataclass(frozen=True)
class Settings:
    # Runtime: dev | production. Production refuses demo defaults.
    app_env: str = "dev"
    log_level: str = "INFO"

    # Auth: local | google | aws
    auth_provider: str = "local"
    allow_local_auth_in_production: bool = False
    login_max_failures: int = 5
    login_lockout_seconds: int = 900
    rate_limit_per_minute: int = 120
    guardrails_enabled: bool = True
    max_question_chars: int = 2000
    cors_origins: tuple[str, ...] = ()  # browser origins allowed to call /api/* (e.g. the demo UI)
    jwt_secret: str = "demo-only-change-me"
    jwt_ttl_seconds: int = 3600
    admin_email: str = "admin@example.com"
    admin_default_password: str = "Admin@123"  # demo only; forced change on first login
    google_client_id: str = ""
    google_hosted_domain: str = ""
    aws_region: str = ""
    cognito_user_pool_id: str = ""
    cognito_client_id: str = ""

    # Storage
    db_path: str = "data/gateway.db"

    # Databricks Genie (through Unity Catalog). Empty -> mock mode.
    databricks_host: str = ""
    # How Genie is called: service_principal (gateway identity) or user_pat (caller's own PAT).
    databricks_auth_mode: str = "service_principal"
    databricks_token: str = ""  # service principal: static PAT of the gateway identity
    databricks_client_id: str = ""  # service principal: OAuth M2M client (preferred over static PAT)
    databricks_client_secret: str = ""
    gateway_encryption_key: str = ""  # Fernet key; encrypts caller PATs held for queued jobs (user_pat mode)
    databricks_pat_auth: bool = True  # accept Databricks PATs as MCP bearer tokens
    databricks_pat_cache_seconds: int = 300
    databricks_account_id: str = ""  # set to sync users from the account; empty = this workspace
    databricks_account_host: str = "https://accounts.cloud.databricks.com"
    genie_space_id: str = ""
    genie_poll_seconds: float = 2.0
    job_timeout_seconds: int = 300

    # Other tools. Empty -> mock mode.
    slack_user_token: str = ""
    jira_base_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""

    # Summarizer for chat context before it reaches Genie: none (truncate) | openai | anthropic
    summarizer_provider: str = "none"
    summarizer_api_key: str = ""
    summarizer_model: str = ""
    summarizer_max_chars: int = 8000

    host: str = "127.0.0.1"
    port: int = 8000

    # Public address (issuer and resource URLs in OAuth metadata). Must be https in production.
    public_base_url: str = ""
    tls_cert_file: str = ""  # serve HTTPS directly; leave empty when a reverse proxy terminates TLS
    tls_key_file: str = ""
    trusted_proxy_ips: str = ""  # e.g. "127.0.0.1" or "*"; forwarded headers accepted only from these

    # OAuth 2.1 authorization server for MCP clients (ChatGPT, Claude, etc.)
    oauth_enabled: bool = True
    oauth_access_token_seconds: int = 3600
    oauth_refresh_token_seconds: int = 2592000
    oauth_allow_dynamic_registration: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        settings = cls(
            app_env=_env("APP_ENV", "dev").lower(),
            log_level=_env("LOG_LEVEL", "INFO").upper(),
            auth_provider=_env("AUTH_PROVIDER", "local").lower(),
            allow_local_auth_in_production=_env("ALLOW_LOCAL_AUTH_IN_PRODUCTION", "false").lower() in ("1", "true", "yes"),
            login_max_failures=int(_env("LOGIN_MAX_FAILURES", "5")),
            login_lockout_seconds=int(_env("LOGIN_LOCKOUT_SECONDS", "900")),
            rate_limit_per_minute=int(_env("RATE_LIMIT_PER_MINUTE", "120")),
            guardrails_enabled=_env("GUARDRAILS_ENABLED", "true").lower() in ("1", "true", "yes"),
            max_question_chars=int(_env("MAX_QUESTION_CHARS", "2000")),
            cors_origins=tuple(o.strip() for o in _env("CORS_ORIGINS").split(",") if o.strip()),
            jwt_secret=_env("JWT_SECRET", cls.jwt_secret),
            jwt_ttl_seconds=int(_env("JWT_TTL_SECONDS", "3600")),
            admin_email=_env("ADMIN_EMAIL", cls.admin_email).lower(),
            admin_default_password=_env("ADMIN_DEFAULT_PASSWORD", cls.admin_default_password),
            google_client_id=_env("GOOGLE_CLIENT_ID"),
            google_hosted_domain=_env("GOOGLE_HOSTED_DOMAIN"),
            aws_region=_env("AWS_REGION"),
            cognito_user_pool_id=_env("COGNITO_USER_POOL_ID"),
            cognito_client_id=_env("COGNITO_CLIENT_ID"),
            db_path=_env("DB_PATH", cls.db_path),
            databricks_host=_env("DATABRICKS_HOST"),
            databricks_auth_mode=_env("DATABRICKS_AUTH_MODE", "service_principal").lower(),
            databricks_token=_env("DATABRICKS_TOKEN"),
            databricks_client_id=_env("DATABRICKS_CLIENT_ID"),
            databricks_client_secret=_env("DATABRICKS_CLIENT_SECRET"),
            gateway_encryption_key=_env("GATEWAY_ENCRYPTION_KEY"),
            databricks_pat_auth=_env("DATABRICKS_PAT_AUTH", "true").lower() in ("1", "true", "yes"),
            databricks_pat_cache_seconds=int(_env("DATABRICKS_PAT_CACHE_SECONDS", "300")),
            databricks_account_id=_env("DATABRICKS_ACCOUNT_ID"),
            databricks_account_host=_env("DATABRICKS_ACCOUNT_HOST", "https://accounts.cloud.databricks.com"),
            summarizer_provider=_env("SUMMARIZER_PROVIDER", "none").lower(),
            summarizer_api_key=_env("SUMMARIZER_API_KEY"),
            summarizer_model=_env("SUMMARIZER_MODEL"),
            summarizer_max_chars=int(_env("SUMMARIZER_MAX_CHARS", "8000")),
            genie_space_id=_env("GENIE_SPACE_ID"),
            genie_poll_seconds=float(_env("GENIE_POLL_SECONDS", "2")),
            job_timeout_seconds=int(_env("JOB_TIMEOUT_SECONDS", "300")),
            slack_user_token=_env("SLACK_USER_TOKEN"),
            jira_base_url=_env("JIRA_BASE_URL"),
            jira_email=_env("JIRA_EMAIL"),
            jira_api_token=_env("JIRA_API_TOKEN"),
            host=_env("HOST", "127.0.0.1"),
            port=int(_env("PORT", "8000")),
            public_base_url=_env("PUBLIC_BASE_URL"),
            tls_cert_file=_env("TLS_CERT_FILE"),
            tls_key_file=_env("TLS_KEY_FILE"),
            trusted_proxy_ips=_env("TRUSTED_PROXY_IPS"),
            oauth_enabled=_env("OAUTH_ENABLED", "true").lower() in ("1", "true", "yes"),
            oauth_access_token_seconds=int(_env("OAUTH_ACCESS_TOKEN_SECONDS", "3600")),
            oauth_refresh_token_seconds=int(_env("OAUTH_REFRESH_TOKEN_SECONDS", "2592000")),
            oauth_allow_dynamic_registration=_env("OAUTH_ALLOW_DYNAMIC_REGISTRATION", "true").lower()
            in ("1", "true", "yes"),
        )
        settings.validate()
        return settings

    def __post_init__(self) -> None:
        # Direct construction (tests, embedding) gets the same checks as from_env.
        self.validate()

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def base_url(self) -> str:
        """Public origin used in OAuth metadata. Falls back to the local listener for development."""
        if self.public_base_url:
            return self.public_base_url.rstrip("/")
        scheme = "https" if self.tls_cert_file else "http"
        return f"{scheme}://{self.host}:{self.port}"

    @property
    def https_enabled(self) -> bool:
        return self.tls_cert_file != ""

    def validate(self) -> None:
        if self.public_base_url and not self.public_base_url.startswith(("https://", "http://")):
            raise ValueError("PUBLIC_BASE_URL must start with https:// (or http:// for local testing)")
        if bool(self.tls_cert_file) != bool(self.tls_key_file):
            raise ValueError("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
        if self.oauth_access_token_seconds < 60 or self.oauth_refresh_token_seconds < 3600:
            raise ValueError("OAUTH_ACCESS_TOKEN_SECONDS must be >= 60 and OAUTH_REFRESH_TOKEN_SECONDS >= 3600")
        if self.is_production:
            if not self.base_url.startswith("https://"):
                raise ValueError("production needs PUBLIC_BASE_URL starting with https://")
            if not self.https_enabled and not self.trusted_proxy_ips:
                raise ValueError(
                    "production needs TLS_CERT_FILE/TLS_KEY_FILE, or TRUSTED_PROXY_IPS when a reverse proxy terminates TLS"
                )

        if self.app_env not in ("dev", "production"):
            raise ValueError("APP_ENV must be dev or production")
        if self.log_level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
            raise ValueError("LOG_LEVEL must be DEBUG, INFO, WARNING or ERROR")
        if self.login_max_failures < 1 or self.login_lockout_seconds < 1 or self.rate_limit_per_minute < 1:
            raise ValueError("LOGIN_MAX_FAILURES, LOGIN_LOCKOUT_SECONDS and RATE_LIMIT_PER_MINUTE must be positive")
        if self.auth_provider not in VALID_PROVIDERS:
            raise ValueError(f"AUTH_PROVIDER must be one of {VALID_PROVIDERS}, got {self.auth_provider!r}")
        if self.is_production:
            if self.jwt_secret in ("", "demo-only-change-me") or len(self.jwt_secret) < 32:
                raise ValueError("production needs JWT_SECRET of at least 32 random characters")
            if self.auth_provider == "local" and not self.allow_local_auth_in_production:
                raise ValueError("production should use SSO; set ALLOW_LOCAL_AUTH_IN_PRODUCTION=true to override")
            if self.auth_provider == "local" and self.admin_default_password == "Admin@123":
                raise ValueError("production needs ADMIN_DEFAULT_PASSWORD changed from the demo default")
        if self.databricks_auth_mode not in DATABRICKS_AUTH_MODES:
            raise ValueError(f"DATABRICKS_AUTH_MODE must be one of {DATABRICKS_AUTH_MODES}")
        if self.databricks_auth_mode == "user_pat":
            if not self.gateway_encryption_key:
                raise ValueError("DATABRICKS_AUTH_MODE=user_pat needs GATEWAY_ENCRYPTION_KEY (Fernet key)")
            try:
                Fernet(self.gateway_encryption_key.encode())
            except (ValueError, TypeError) as exc:
                raise ValueError("GATEWAY_ENCRYPTION_KEY is not a valid Fernet key") from exc
        if self.databricks_host and self.databricks_auth_mode == "service_principal" and not self.service_credentials_present:
            if self.genie_space_id:
                raise ValueError(
                    "DATABRICKS_AUTH_MODE=service_principal needs DATABRICKS_CLIENT_ID+DATABRICKS_CLIENT_SECRET "
                    "or DATABRICKS_TOKEN"
                )
        if self.summarizer_provider not in SUMMARIZER_PROVIDERS:
            raise ValueError(f"SUMMARIZER_PROVIDER must be one of {SUMMARIZER_PROVIDERS}")
        if self.summarizer_provider != "none" and not (self.summarizer_api_key and self.summarizer_model):
            raise ValueError("SUMMARIZER_PROVIDER needs SUMMARIZER_API_KEY and SUMMARIZER_MODEL")
        if self.auth_provider == "google" and not self.google_client_id:
            raise ValueError("AUTH_PROVIDER=google needs GOOGLE_CLIENT_ID")
        if self.auth_provider == "aws" and not (self.aws_region and self.cognito_user_pool_id and self.cognito_client_id):
            raise ValueError("AUTH_PROVIDER=aws needs AWS_REGION, COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID")

    @property
    def pat_auth_enabled(self) -> bool:
        return self.databricks_pat_auth and bool(self.databricks_host)

    @property
    def service_credentials_present(self) -> bool:
        return bool(self.databricks_token or (self.databricks_client_id and self.databricks_client_secret))

    @property
    def genie_live(self) -> bool:
        if not (self.databricks_host and self.genie_space_id):
            return False
        return self.databricks_auth_mode == "user_pat" or self.service_credentials_present

    @property
    def slack_live(self) -> bool:
        return bool(self.slack_user_token)

    @property
    def jira_live(self) -> bool:
        return bool(self.jira_base_url and self.jira_email and self.jira_api_token)

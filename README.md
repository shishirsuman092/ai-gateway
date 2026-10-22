# Genie gateway (MCP)

An MCP server that takes plain-text questions and routes them to **Databricks Genie** (governed by
Unity Catalog), **Slack**, or **Jira**. Work is asynchronous: `submit_query` returns a `job_id` at once,
and `get_query_result` returns the answer when it is ready. Every query is kept in a chat history.

## Features

- **Async jobs:** submit, then poll or long-poll (`wait_seconds` up to 60). Jobs and chats persist in SQLite.
- **Tools:** `genie` (default), `slack`, `jira`. Pick one with `tool=`, a `genie:` / `slack:` / `jira:` prefix, or keywords.
- **Genie identity by config:** run as the gateway's service principal (`DATABRICKS_AUTH_MODE=service_principal`) or as each caller's own PAT (`user_pat`).
- **Databricks PAT login:** user and service-principal PATs are verified against the workspace and mapped to gateway accounts.
- **Directory sync:** list and import every user and service principal in the workspace or account.
- **Chat history:** conversations keep the questions sent, the summaries used, and the answers. Follow-ups continue the same Genie conversation.
- **Context summarization:** earlier chat is summarized (by the client, or by the gateway through OpenAI or Anthropic) before it reaches Genie.
- **Auth:** `local` (bcrypt + JWT), `google` (OIDC), or `aws` (Cognito OIDC), selected with `AUTH_PROVIDER`.
- **OAuth 2.1 for MCP clients:** PKCE authorization code, dynamic client registration, rotating refresh tokens.
- **HTTPS:** TLS served directly, or terminated by a reverse proxy (Caddy example included), with HSTS.
- **RBAC:** `admin` manages users, roles, tool grants and the directory, and can use every tool. `user` needs a grant per tool.
- **Guardrails, audit, rate limits, lockout:** see [Guardrails](#guardrails) and [Enterprise controls](#enterprise-controls).
- **Mock mode:** Genie, Slack and Jira run as stubs until their credentials are set.

## Quick start (demo, local auth)

```bash
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env                                  # defaults run in mock mode
set -a; . ./.env; set +a
python -m genie_gateway                               # http://127.0.0.1:8000/mcp
```

1. Log in as `admin@example.com` / `Admin@123` at `POST /auth/login`. The server forces a password change.
2. `POST /auth/change-password` with `old_password` and `new_password` (8+ characters).
3. Create a user: `POST /admin/users` with `{"email", "password", "role", "tools": ["genie","jira"]}`. The user must change the password at first login.
4. Point an MCP client at `http://127.0.0.1:8000/mcp` with `Authorization: Bearer <access_token>`.

Demo defaults are for local use only. Set `APP_ENV=production` and real secrets before any shared deployment.

## Configuration

Everything is set through environment variables (see `.env.example`).

| Area | Variables |
|---|---|
| Runtime | `APP_ENV` (`dev` / `production`), `LOG_LEVEL`, `HOST`, `PORT`, `DB_PATH` |
| Auth provider | `AUTH_PROVIDER`, `JWT_SECRET`, `JWT_TTL_SECONDS`, `ADMIN_EMAIL`, `ADMIN_DEFAULT_PASSWORD`, `ALLOW_LOCAL_AUTH_IN_PRODUCTION` |
| SSO | `GOOGLE_CLIENT_ID`, `GOOGLE_HOSTED_DOMAIN`, `AWS_REGION`, `COGNITO_USER_POOL_ID`, `COGNITO_CLIENT_ID` |
| Databricks | `DATABRICKS_HOST`, `DATABRICKS_AUTH_MODE`, `DATABRICKS_CLIENT_ID`, `DATABRICKS_CLIENT_SECRET`, `DATABRICKS_TOKEN`, `GATEWAY_ENCRYPTION_KEY`, `DATABRICKS_PAT_AUTH`, `DATABRICKS_PAT_CACHE_SECONDS`, `DATABRICKS_ACCOUNT_ID`, `DATABRICKS_ACCOUNT_HOST`, `GENIE_SPACE_ID`, `GENIE_POLL_SECONDS`, `JOB_TIMEOUT_SECONDS` |
| Summarizer | `SUMMARIZER_PROVIDER` (`none` / `openai` / `anthropic`), `SUMMARIZER_API_KEY`, `SUMMARIZER_MODEL`, `SUMMARIZER_MAX_CHARS` |
| Slack / Jira | `SLACK_USER_TOKEN`, `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN` |
| Guardrails and limits | `GUARDRAILS_ENABLED`, `MAX_QUESTION_CHARS`, `RATE_LIMIT_PER_MINUTE`, `LOGIN_MAX_FAILURES`, `LOGIN_LOCKOUT_SECONDS` |
| HTTPS | `PUBLIC_BASE_URL`, `TLS_CERT_FILE`, `TLS_KEY_FILE`, `TRUSTED_PROXY_IPS`, `PUBLIC_HOST` (Caddy) |
| OAuth | `OAUTH_ENABLED`, `OAUTH_ACCESS_TOKEN_SECONDS`, `OAUTH_REFRESH_TOKEN_SECONDS`, `OAUTH_ALLOW_DYNAMIC_REGISTRATION` |

`APP_ENV=production` refuses to start unless the configuration is safe: a real `JWT_SECRET` (32+ characters), an https `PUBLIC_BASE_URL`, TLS files or a trusted proxy, and SSO (or an explicit local-auth override with a changed admin password).

## Authentication

Every request to `/mcp` and the admin and API routes needs a bearer token. Three kinds are accepted, under any `AUTH_PROVIDER`:

| Token | Who | How it is checked |
|---|---|---|
| Gateway JWT | local users (`POST /auth/login`) | signed by `JWT_SECRET`, revocable |
| OAuth access token | MCP clients that completed the OAuth flow | signed by `JWT_SECRET`, `aud` = `<base>/mcp`, revocable |
| Databricks PAT (`dapi...`) | users and service principals | verified against the workspace (see below) |
| Provider ID token | Google or Cognito users under SSO | verified against the provider's JWKS |

### Databricks PAT

The gateway checks a PAT with `GET {DATABRICKS_HOST}/api/2.0/preview/scim/v2/Me` and maps the identity to a gateway account:

| PAT owner | Identity key | Gateway account | Create with |
|---|---|---|---|
| User | `userName` (email) | `kind=human`, role and tool grants | `POST /admin/users` `{"email", "role", "tools"}` |
| Service principal | `applicationId` (UUID) | `kind=service`, no password | `POST /admin/users` `{"email": "<applicationId>", "kind": "service", "tools"}` |

Rules:
- PATs never auto-provision. The admin creates the account first (or imports it through directory sync). An unknown identity gets `401`.
- A disabled gateway account, or an inactive Databricks account, gets `401`.
- A PAT cannot claim an account of the other kind.
- Verified identities are cached by the SHA-256 of the token for `DATABRICKS_PAT_CACHE_SECONDS` (default 300). A revoked PAT stops working after at most that long.
- `DATABRICKS_PAT_AUTH=false` refuses PATs and keeps only JWT and SSO.
- Service accounts cannot log in with a password or use `/auth/change-password`.

**Simplified onboarding:** the admin supplies only the PAT, role and tools. The workspace identifies the owner, and the gateway creates or updates the account.

```bash
# API (admin bearer token required); the PAT is sent once and not stored
curl -s -X POST https://gw.example.com/admin/accounts/from-pat \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"pat": "dapi...", "role": "user", "tools": ["genie", "jira"]}'

# CLI (token from an environment variable or a hidden prompt)
TEST_PAT=dapi... python -m genie_gateway add-pat --token-env TEST_PAT --role user --tools genie,jira
```

Send PATs only over TLS. The audit log records the identity and the action, never the token.

### SSO providers

| `AUTH_PROVIDER` | Required settings | Token the client sends |
|---|---|---|
| `local` | `JWT_SECRET` | token from `/auth/login` |
| `google` | `GOOGLE_CLIENT_ID` (optional `GOOGLE_HOSTED_DOMAIN`) | Google ID token |
| `aws` | `AWS_REGION`, `COGNITO_USER_POOL_ID`, `COGNITO_CLIENT_ID` | Cognito ID or access token |

With SSO, password login is disabled. The first sign-in from an SSO account creates a user with no tool grants. The admin is matched by email, so set `ADMIN_EMAIL` to the SSO account that should be admin before the first boot. If the database already has an admin, promote the SSO user from that admin.

## Genie identity

`DATABRICKS_AUTH_MODE` picks whose identity runs Genie queries:

| Mode | Genie runs as | Needs |
|---|---|---|
| `service_principal` (default) | the gateway's own identity | `DATABRICKS_CLIENT_ID` + `DATABRICKS_CLIENT_SECRET` (OAuth M2M, refreshed automatically), or a static `DATABRICKS_TOKEN` |
| `user_pat` | the caller's own Databricks PAT, per query | `GATEWAY_ENCRYPTION_KEY` (Fernet key). Callers must send a PAT as the bearer token. |

In `user_pat` mode the PAT is encrypted while the job is queued and erased as soon as the job reads it. Unity Catalog then applies per user. A `user_pat` query without a PAT is refused. Startup fails if the key is missing or the service credentials are absent.

Generate a Fernet key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Users from Databricks (directory sync)

- `GET /admin/databricks/directory?include_service_principals=true`: lists every user and service principal, paged. Read only.
- `POST /admin/databricks/directory/sync` with `{"dry_run": true, "role": "user", "tools": ["genie"]}`: creates gateway accounts for entries that do not exist yet. Existing accounts are never overwritten. Inactive Databricks accounts are skipped and reported.
- Scope: workspace SCIM by default. Set `DATABRICKS_ACCOUNT_ID` to read account-level SCIM (all workspaces in the account).
- The credential needs directory read rights (workspace admin, or account admin for account scope).

Users created by sync can log in with a PAT immediately, because the PAT check finds their account.

## MCP tools

| Tool | Purpose |
|---|---|
| `submit_query(question, tool?, conversation_id?, chat_context?, context_summary?)` | Start a job; returns `job_id`, `conversation_id` and `status` |
| `get_query_result(job_id, wait_seconds?)` | Status, answer, SQL, or error |
| `list_my_queries(limit?)` | Your recent jobs |
| `list_conversations(limit?)` | Your saved chats, newest first |
| `get_conversation(conversation_id)` | A chat with every message sent and answer received |
| `list_available_tools()` | Tools you may use |

Example result for a Genie job:

```json
{"job_id": "…", "tool": "genie", "status": "COMPLETED", "conversation_id": "…",
 "result": {"mode": "live", "answer": "…", "sql": "SELECT …", "conversation_id": "…"}}
```

## Chat history and context

- Every `submit_query` belongs to a conversation. Omit `conversation_id` to start one; the response returns it. Pass it back to continue the chat.
- Stored per message: the user question (after redaction), any summary sent to Genie, and the answer. Raw chat context is not stored.
- Follow-up questions in a conversation continue the same Genie conversation.
- Chats are private to their owner. Admins can read any chat.
- REST: `GET /api/conversations`, `GET /api/conversations/{id}`.

### Sending chat context to Genie

`submit_query` accepts two optional fields:

| Field | Meaning |
|---|---|
| `chat_context` | Raw earlier chat text. The gateway summarizes it, then sends `Conversation context: <summary>` followed by the question to Genie. |
| `context_summary` | A summary the client already made. Sent as-is; no summarizer call. |

The summarizer is set by `SUMMARIZER_PROVIDER`:
- `none` (default): keeps the most recent `SUMMARIZER_MAX_CHARS` characters, prefixed with a truncation marker.
- `openai` or `anthropic`: calls the provider with `SUMMARIZER_API_KEY` and `SUMMARIZER_MODEL`. If the call fails, the gateway falls back to truncation.

Summaries pass through redaction before they reach Genie or the history.

Recommended pattern: the chat client summarizes with its own LLM and passes `context_summary`. The summarizer key then stays out of the gateway.

## HTTPS

- Production requires `PUBLIC_BASE_URL=https://...` and either `TLS_CERT_FILE` with `TLS_KEY_FILE` (uvicorn serves TLS), or `TRUSTED_PROXY_IPS` (a reverse proxy terminates TLS).
- HSTS (`max-age=31536000; includeSubDomains`) is sent whenever the public URL is https.
- Forwarded headers (`X-Forwarded-Proto`, `X-Forwarded-For`) are trusted only from `TRUSTED_PROXY_IPS`.
- Recommended: `docker compose up -d --build`. Caddy (see `deploy/Caddyfile`) obtains a Let's Encrypt certificate for `PUBLIC_HOST` and forwards to the gateway, which is reachable only inside the compose network.

## OAuth for MCP clients (ChatGPT, Claude, others)

The gateway is its own OAuth 2.1 authorization server, following the MCP authorization specification:

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/oauth-protected-resource` | resource metadata (`<base>/mcp`) |
| `GET /.well-known/oauth-authorization-server` | issuer, endpoints, PKCE S256 |
| `POST /oauth/register` | dynamic client registration (public clients) |
| `GET/POST /oauth/authorize` | login page: Databricks PAT, or email and password with `AUTH_PROVIDER=local` |
| `POST /oauth/token` | `authorization_code` (PKCE required) and `refresh_token` (rotating) |

`/mcp` answers `401` with `WWW-Authenticate: Bearer resource_metadata="..."`, which starts the flow.

Flow: the client reads the metadata, registers, opens `/oauth/authorize` in the user's browser, the user signs in, the client receives a code, exchanges it with the PKCE verifier, and then calls `/mcp` with the access token.

Details:
- Access tokens: HS256 JWT signed with `JWT_SECRET`, `aud` = `<base>/mcp`, lifetime `OAUTH_ACCESS_TOKEN_SECONDS` (default 3600). Revocable by `jti`.
- Refresh tokens: 30 days by default, rotated on each use. Replaying an old refresh token is refused.
- Authorization codes: single use, valid 60 seconds.
- Redirect URIs: `https://` only, or `http://localhost` / `127.0.0.1` for local tools. Matched exactly against the registered list.
- The login page sends CSP `default-src 'none'` and `frame-ancestors 'none'`, and carries a CSRF token bound to the request.

Limits:
- Browser sign-in with Google or Cognito is not built. On SSO servers the login page accepts only a Databricks PAT.
- Dynamic registration is open by default. Set `OAUTH_ALLOW_DYNAMIC_REGISTRATION=false` if clients must be registered another way.
- `POST /auth/logout` revokes gateway JWTs only. OAuth tokens expire on their own, or the user's account is disabled.
- Connector compatibility with ChatGPT is written to the MCP spec. Verify it against the live endpoint.

Clients that accept a bearer header can also use a PAT directly: `Authorization: Bearer <token>`.

## Architecture

```
MCP / REST client ──Bearer──► BearerAuthMiddleware ──► FastMCP tools + REST routes
  (PAT, JWT, OAuth token)        │  rate limits, request IDs,        │
                                 │  security headers, HSTS           ▼
                          AuthService ◄── OAuthService          JobService ──► ToolRegistry
                          (PAT → SCIM Me,   (/oauth/*,           │  guardrails,   ├─ GenieAdapter
                           JWT, OIDC)        PKCE, tokens)        │  encrypted     │   (service principal
                                 │                                 │  PAT per job  │    or caller PAT)
                          UserService / RBAC              ChatService (history)    ├─ SlackAdapter
                                 │                                 │               └─ JiraAdapter
                          DatabricksDirectory (SCIM sync)   Summarizer (context)
                                 │
                          SQLite (users, jobs, chats, audit, OAuth, revocations)
```

## Guardrails

Applied to every plain-text query (`GUARDRAILS_ENABLED`, default on):

| Stage | Rule | Result |
|---|---|---|
| Input | length over `MAX_QUESTION_CHARS` (2000) | blocked, audited as `query.blocked` |
| Input | control characters | blocked |
| Input | prompt-injection phrases (ignore instructions, reveal system prompt, etc.) | blocked |
| Input | secrets (PAT, AWS key, JWT, Bearer, Slack token, `password=`) and PII (email, Luhn-valid card, SSN, IBAN) | redacted to `[REDACTED:<kind>]` before the tool runs |
| Chat context | secrets and PII | redacted before summarization and storage |
| SQL | write or DDL statement in generated SQL (`INSERT`, `DELETE`, `DROP`, `GRANT`, ...) | SQL dropped from the result |
| Output | secrets and PII in the answer | redacted; kinds listed in `result.guardrails` |

These are heuristics. Unity Catalog grants remain the real data boundary. Tune the patterns in `genie_gateway/guardrails.py`.

## Enterprise controls

- **Audit log:** append-only table `audit_log`, mirrored to the log stream. Events include `auth.login` (success, failure, denied), `auth.logout`, `oauth.client_registered`, `oauth.code_issued`, `oauth.token_issued`, `query.submit`, `query.denied`, `query.blocked`, `query.redacted`, `result.redacted`, `directory.sync`. Read with `GET /admin/audit?actor=&action=&limit=` (admin only).
- **Login lockout:** `LOGIN_MAX_FAILURES` (5) failures lock the account for `LOGIN_LOCKOUT_SECONDS` (900). All failures return the same message, so accounts cannot be enumerated.
- **Revocation:** `POST /auth/logout` revokes the gateway JWT by `jti` until it expires.
- **Rate limits:** token bucket per client IP and per user, `RATE_LIMIT_PER_MINUTE` (120). Returns `429` with `Retry-After`.
- **Observability:** JSON logs with `request_id`; a well-formed `X-Request-ID` from the client is kept. `GET /metrics` (admin, Prometheus text). `GET /ready` checks the database and reports the schema version. `GET /health` is liveness.
- **Headers:** `nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and HSTS over https.
- **Schema:** versioned migrations via `PRAGMA user_version`. WAL mode on disk.

## Deploy

```bash
cp .env.example .env     # set APP_ENV=production, JWT_SECRET, PUBLIC_HOST, PUBLIC_BASE_URL, SSO settings
docker compose up -d --build
```

- The gateway container runs as non-root, with a read-only root filesystem and all capabilities dropped.
- Caddy (`deploy/Caddyfile`) terminates TLS on ports 80 and 443. The gateway port is not published.
- CI (`.github/workflows/ci.yml`) runs the tests on Python 3.11 and 3.12 and builds the image.

Scaling: SQLite is single-writer and jobs run in-process. Run one replica, or move storage to Postgres and jobs to a queue before scaling out.

## Limits and next steps

- SQLite and in-process workers suit a single instance.
- Jira plain-text search becomes `text ~ "…"`. Natural-language-to-JQL is not implemented; use `jql:` for exact queries.
- Browser sign-in for OAuth on SSO servers is not built.
- Guardrails are pattern-based heuristics.

## Tests

```bash
pytest
```

The suite covers: job lifecycle and failure handling; RBAC; token checks for each provider (fake signing keys); the PAT flow for users and service principals; the admin and auth HTTP flow; the OAuth authorization code, PKCE, refresh rotation and registration flow; HTTPS and production configuration checks; Genie identity modes (service principal OAuth, caller PAT, encryption at rest); chat history and privacy; context summarization with fallback; directory pagination and sync; guardrails; migrations from older databases; and an end-to-end MCP client run against a live server.

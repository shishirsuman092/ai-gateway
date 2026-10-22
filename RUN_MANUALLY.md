# Run the gateway manually

Steps to start, test, and stop the Genie gateway by hand on Windows. Use PowerShell unless noted.
Commands assume the project folder `C:\Users\sisir\Documents\AI-assistant`.

## 1. One-time setup

```powershell
cd C:\Users\sisir\Documents\AI-assistant
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Create `.env` from the template if it does not exist, then edit it:

```powershell
Copy-Item .env.example .env
notepad .env
```

Set at least:

| Variable | Value |
|---|---|
| `APP_ENV` | `dev` for local runs |
| `JWT_SECRET` | any random string, 32+ characters |
| `ADMIN_DEFAULT_PASSWORD` | your choice (forced change at first login) |
| `DATABRICKS_HOST`, `GENIE_SPACE_ID` | your workspace and Genie space (leave empty for mock mode) |
| `DATABRICKS_CLIENT_ID`, `DATABRICKS_CLIENT_SECRET` | service principal OAuth credentials (or `DATABRICKS_TOKEN`) |

Never commit `.env`. Rotate any secret that was pasted into a chat or a log.

## 2. Start the gateway (local only)

Use this when testing with curl or a local MCP client on the same machine.

```powershell
cd C:\Users\sisir\Documents\AI-assistant
Get-Content .env | ForEach-Object {
  if ($_ -match '^\s*([A-Z_][A-Z0-9_]*)=([^#]*)') { [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2].Trim(), 'Process') }
}
.\.venv\Scripts\python.exe -m genie_gateway
```

The server listens on `http://127.0.0.1:8000`. Check it from a second terminal:

```powershell
curl.exe http://127.0.0.1:8000/health
curl.exe http://127.0.0.1:8000/ready
```

Leave the first terminal open. Stop with `Ctrl+C`.

## 3. Start with a public HTTPS tunnel (for ChatGPT or Claude Desktop)

ChatGPT and Claude Desktop need a public `https://` URL. Use Cloudflare's quick tunnel.

Install once:

```powershell
winget install --id Cloudflare.cloudflared -e
```

Terminal A: start the tunnel first and note the URL it prints (`https://<random>.trycloudflare.com`).

```powershell
& "C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://127.0.0.1:8000
```

Terminal B: start the gateway with that URL as its public base. Replace `<random>`.

```powershell
cd C:\Users\sisir\Documents\AI-assistant
$env:PUBLIC_BASE_URL = "https://<random>.trycloudflare.com"
$env:APP_ENV = "dev"
Get-Content .env | ForEach-Object {
  if ($_ -match '^\s*([A-Z_][A-Z0-9_]*)=([^#]*)') { [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2].Trim(), 'Process') }
}
$env:PUBLIC_BASE_URL = "https://<random>.trycloudflare.com"   # re-set: .env may override it
.\.venv\Scripts\python.exe -m genie_gateway
```

Order matters: start the tunnel, then the gateway, because the gateway writes the public URL into its OAuth metadata at startup. A new tunnel URL needs a gateway restart.

Check the public side:

```powershell
curl.exe https://<random>.trycloudflare.com/health
curl.exe https://<random>.trycloudflare.com/.well-known/oauth-protected-resource
```

The metadata `resource` field must show your tunnel URL plus `/mcp`.

Connector URL to enter in ChatGPT or Claude Desktop: `https://<random>.trycloudflare.com/mcp` (auth: OAuth).

If the tunnel returns `522`, wait a minute and retry, or restart `cloudflared`. Restarting it changes the URL; repeat step 3.

## 4. Verify the OAuth login by hand (optional)

```powershell
curl.exe -i -X POST http://127.0.0.1:8000/auth/login -H "content-type: application/json" -d "{\"email\":\"admin@example.com\",\"password\":\"<password>\"}"
```

A response with `"must_change_password": true` means the admin password must be changed first:

```powershell
curl.exe -X POST http://127.0.0.1:8000/auth/change-password -H "Authorization: Bearer <access_token>" -H "content-type: application/json" -d "{\"old_password\":\"<old>\",\"new_password\":\"<new, 8+ chars>\"}"
```

## 5. Stop everything

```powershell
# gateway on port 8000
$pid8000 = (Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue).OwningProcess
if ($pid8000) { Stop-Process -Id $pid8000 -Force }

# tunnel
Stop-Process -Name cloudflared -Force -ErrorAction SilentlyContinue
```

Confirm nothing is left:

```powershell
Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
Get-Process cloudflared -ErrorAction SilentlyContinue
```

Both commands should print nothing.

## 6. Run the tests

```powershell
cd C:\Users\sisir\Documents\AI-assistant
.\.venv\Scripts\python.exe -m pytest -q
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Address already in use` on 8000 | old gateway still running | run the stop block in step 5 |
| `invalid_grant` / `response_type must be code` | old gateway code running | restart the gateway |
| `421 Misdirected Request` through tunnel | public host not allowed | restart after pulling the latest code; `PUBLIC_BASE_URL` must match the tunnel URL |
| `522` from tunnel | tunnel or origin unreachable | retry; restart `cloudflared` if persistent (URL changes) |
| `production needs ...` at startup | `APP_ENV=production` with dev settings | set `APP_ENV=dev` for local runs |
| Genie errors | wrong `DATABRICKS_HOST`, `GENIE_SPACE_ID`, or credentials | check `.env`; leave `GENIE_SPACE_ID` empty for mock mode |

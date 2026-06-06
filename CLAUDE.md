# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A FastAPI web application that acts as an MCP (Model Context Protocol) client. It authenticates against an OAuth 2.1 provider using Authorization Code Flow + PKCE, then uses the acquired access token to connect to an MCP server over SSE or Streamable HTTP transport and expose its tools, prompts, and resources through a browser UI.

## Commands

### Run locally (Python 3.12+)
```bash
pip install -r requirements.txt
python main.py          # starts uvicorn with --reload on port 8000
```

### Run with Docker
```bash
cp .env.example .env    # then edit .env with real values
docker compose up --build
```

### Environment setup
All configuration comes from environment variables. Copy `.env.example` to `.env` and fill in:
- `CLIENT_ID`, `CLIENT_SECRET` — OAuth 2.1 app credentials
- `OAUTH_AUTH_URL`, `OAUTH_TOKEN_URL`, `OAUTH_SCOPE` — OAuth provider endpoints (used as fallback if MCP server doesn't expose discovery)
- `MCP_SERVER_URL` — MCP server endpoint URL
- `MCP_TRANSPORT` — `sse` (default) or `streamable_http`
- `REDIRECT_URI` — must match what's registered with the OAuth provider
- `SECRET_KEY` — generate with `python -c "import secrets; print(secrets.token_hex(32))"`

There is no test suite. Manual testing is done via Docker Compose with a real OAuth provider and MCP server. The app's FastAPI docs are available at `/docs`.

## Architecture

The entire backend is `main.py` (one file). The frontend is `templates/index.html` (a single-page app using Tailwind CSS and vanilla JS, served via Jinja2).

### OAuth 2.1 + PKCE flow
1. `GET /login` — Attempts OAuth discovery from `{MCP_SERVER_URL}/.well-known/oauth-authorization-server` (tries both the full path and origin-only). If the server exposes a `registration_endpoint`, registers a new public client dynamically (RFC 7591) — this takes priority over the configured `CLIENT_ID`. Generates a PKCE pair and state token, stores them in the session, and redirects to the authorization URL.
2. `GET /callback` — Validates state (CSRF check), exchanges the code for tokens using the stored PKCE verifier, and decodes the `id_token` JWT payload (no signature verification) to extract the user's email.
3. `GET /logout` — Clears the session.

### MCP session pattern
Every `/api/*` route opens a fresh MCP `ClientSession` per request via `_with_mcp_session()`. This helper wraps both transport types:
- SSE: `sse_client(url, headers=...)` → `ClientSession`
- Streamable HTTP: `streamablehttp_client(url, headers=...)` → `ClientSession` (requires `mcp>=1.2`; guarded by `_HAS_STREAMABLE_HTTP`)

The Bearer token is injected as an `Authorization` header on the transport-level HTTP client.

### Runtime config override
The MCP server URL and transport can be changed at runtime through the UI without restarting. `POST /api/config` stores the new values in the session. Helper functions `_sess_url()` and `_sess_transport()` read from the session first, falling back to environment variables. Changing the server URL automatically clears the auth session (different server = different OAuth realm).

### Session storage
`SessionMiddleware` from Starlette stores everything in a signed+encrypted cookie (max 1 hour). Session keys: `access_token`, `refresh_token`, `user_email`, `mcp_server_url`, `mcp_transport`, and ephemeral OAuth state (`pkce_verifier`, `oauth_state`, `_token_url`, `_client_id`, `_use_secret`).

### MCP capabilities exposed
| Route | MCP operation |
|---|---|
| `GET /api/tools` | `tools/list` |
| `POST /api/call-tool` | `tools/call` |
| `GET /api/prompts` | `prompts/list` |
| `POST /api/get-prompt` | `prompts/get` |
| `GET /api/resources` | `resources/list` |
| `POST /api/read-resource` | `resources/read` |

Prompts and resources gracefully handle `McpError` if the server doesn't support them (returns empty list rather than erroring).

### Debug endpoints
- `GET /api/debug/discovery` — Fetches and returns the OAuth discovery metadata from the MCP server
- `GET /api/debug/token` — Decodes the current session's JWT claims (no signature verification)
- `GET /health` — Health check (used by Docker Compose)

### Error handling
`_extract_error()` unwraps Python `ExceptionGroup` / `TaskGroup` exceptions (from `except*` syntax used in the streamable_http path) to surface the real underlying error with user-friendly hints for common HTTP status codes (401, 403, 405). `_http_status_for()` maps exception types to appropriate HTTP status codes for API responses.

# MCP Web Client

A Python web application that acts as an **MCP (Model Context Protocol) Client** for testing MCP Server connections and tool capabilities. It authenticates via **OAuth 2.1 Authorization Code Flow with PKCE**, then uses the acquired Access Token to connect to an MCP Server over HTTP/SSE or Streamable HTTP transport.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)
![MCP](https://img.shields.io/badge/MCP-1.27-purple)
![Docker](https://img.shields.io/badge/Docker-ready-blue)

---

## Features

- **OAuth 2.1 + PKCE** — Full Authorization Code Flow with CSRF protection and PKCE (S256) for secure token acquisition
- **List Tools** — Connects to an MCP Server and displays all available tools with their descriptions and input schemas
- **Call Tool** — Executes any tool with custom JSON arguments and displays the result in real time
- **Dual transport support** — Works with both SSE (`sse`) and Streamable HTTP (`streamable_http`) MCP transports
- **Docker-ready** — Multi-stage Dockerfile for lean production images; `docker-compose.yml` for one-command startup

---

## Architecture

```
Browser
  │
  ├─ GET /login          →  Redirect to OAuth Provider (Authorization URL + PKCE)
  ├─ GET /callback       →  Exchange code for Access Token (token endpoint)
  │
  ├─ GET /api/tools      →  FastAPI opens MCP session → list_tools() → returns JSON
  └─ POST /api/call-tool →  FastAPI opens MCP session → call_tool() → returns result
                                        │
                          Bearer token injected as Authorization header
                                        │
                              MCP Server (HTTP/SSE or Streamable HTTP)
```

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/)
- An **OAuth 2.1** provider (e.g. CyberArk Identity, Auth0, Keycloak) with a registered application
- A running **MCP Server** accessible over HTTP

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/huydd79/mcp-web-client.git
cd mcp-web-client
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` with your values:

```env
# OAuth 2.1 provider credentials
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
OAUTH_AUTH_URL=https://your-provider.com/OAuth2/Authorize
OAUTH_TOKEN_URL=https://your-provider.com/OAuth2/Token
OAUTH_SCOPE=openid profile

# Redirect URI — must match what is registered in your OAuth provider
REDIRECT_URI=http://localhost:8000/callback

# MCP Server endpoint
MCP_SERVER_URL=https://your-mcp-server.com/mcp/endpoint

# Transport: "sse" (classic) | "streamable_http" (MCP spec ≥ 2025-11-05)
MCP_TRANSPORT=streamable_http

# Session signing key — generate with: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=change-me
```

### 3. Build and run

```bash
docker compose up --build
```

Open **http://localhost:8000** in your browser.

---

## Usage

1. **Log in** — Click *"Log in via OAuth"*. You will be redirected to your OAuth provider's login page.
2. **Authenticate** — After successful login, you are redirected back to the app with an Access Token stored in the session.
3. **List Tools** — Click *"Connect & List Tools"*. The app connects to the MCP Server using the Bearer token and fetches all available tools.
4. **Execute a Tool** — Click any tool card, fill in the JSON arguments, and click *"Execute"*. The result appears in the right panel.

---

## Running without Docker

```bash
pip install -r requirements.txt
python main.py
```

Requires Python 3.12+.

---

## Project Structure

```
mcp-web-client/
├── main.py               # FastAPI application (OAuth flow + MCP client logic)
├── templates/
│   └── index.html        # Single-page UI (Tailwind CSS + vanilla JS)
├── requirements.txt
├── Dockerfile            # Multi-stage build (deps stage + slim runtime stage)
├── docker-compose.yml
└── .env.example          # Environment variable template
```

## Key files

| File | Description |
|------|-------------|
| [main.py](main.py) | OAuth 2.1 routes (`/login`, `/callback`, `/logout`) and MCP API routes (`/api/tools`, `/api/call-tool`) |
| [templates/index.html](templates/index.html) | Web UI — tool browser and executor |
| [Dockerfile](Dockerfile) | Two-stage build: installs deps in a builder image, copies only packages to a slim runtime image |
| [docker-compose.yml](docker-compose.yml) | Service definition with health check; reads config from `.env` |

---

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `CLIENT_ID` | Yes | OAuth client ID |
| `CLIENT_SECRET` | No | OAuth client secret (omit for public clients) |
| `OAUTH_AUTH_URL` | Yes | Authorization endpoint URL |
| `OAUTH_TOKEN_URL` | Yes | Token endpoint URL |
| `OAUTH_SCOPE` | Yes | Requested OAuth scopes (space-separated) |
| `REDIRECT_URI` | Yes | Callback URL registered in the OAuth provider |
| `MCP_SERVER_URL` | Yes | MCP Server endpoint URL |
| `MCP_TRANSPORT` | No | `sse` (default) or `streamable_http` |
| `SECRET_KEY` | Yes | Random hex string for signing session cookies |

---

## License

MIT

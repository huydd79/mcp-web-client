"""
MCP Web Client
==============
FastAPI application that acts as an MCP Client with OAuth 2.1 Authorization Code
Flow + PKCE. After authentication, it connects to an MCP Server over HTTP/SSE
(or Streamable HTTP) and exposes List Tools / Call Tool functionality.

Environment variables (see .env.example):
    CLIENT_ID, CLIENT_SECRET, REDIRECT_URI
    OAUTH_AUTH_URL, OAUTH_TOKEN_URL, OAUTH_SCOPE
    MCP_SERVER_URL, MCP_TRANSPORT  (sse | streamable_http)
    SECRET_KEY
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
from typing import Any
from urllib.parse import urlencode

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from mcp import ClientSession
from mcp.client.sse import sse_client
from starlette.middleware.sessions import SessionMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

# ── Streamable HTTP transport (MCP spec ≥ 2025-11-05) ────────────────────────
try:
    from mcp.client.streamable_http import streamablehttp_client

    _HAS_STREAMABLE_HTTP = True
except ImportError:
    _HAS_STREAMABLE_HTTP = False

# ─────────────────────────────────────────────────────────────────────────────
# Configuration  (all values come from environment variables)
# ─────────────────────────────────────────────────────────────────────────────
CLIENT_ID = os.getenv("CLIENT_ID", "your-client-id")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8001/sse")
MCP_TRANSPORT = os.getenv("MCP_TRANSPORT", "sse")  # "sse" | "streamable_http"
OAUTH_AUTH_URL = os.getenv("OAUTH_AUTH_URL", "https://auth.example.com/authorize")
OAUTH_TOKEN_URL = os.getenv("OAUTH_TOKEN_URL", "https://auth.example.com/token")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8000/callback")
OAUTH_SCOPE = os.getenv("OAUTH_SCOPE", "openid profile")
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
# Set HTTPS_ONLY=true when running behind an HTTPS reverse proxy (nginx, Traefik, etc.)
# This adds the Secure flag to the session cookie so the browser only sends it over HTTPS.
HTTPS_ONLY = os.getenv("HTTPS_ONLY", "false").lower() == "true"

# ─────────────────────────────────────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="MCP Web Client", docs_url="/docs")

# ProxyHeadersMiddleware must be outermost (added last) so it runs first on each
# request and rewrites host/scheme from X-Forwarded-Proto/X-Forwarded-For before
# SessionMiddleware reads them.
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=3600, https_only=HTTPS_ONLY)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

templates = Jinja2Templates(directory="templates")


# ─────────────────────────────────────────────────────────────────────────────
# PKCE helpers  (OAuth 2.1 requires PKCE for public and confidential clients)
# ─────────────────────────────────────────────────────────────────────────────
def _pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) using S256 method."""
    verifier = (
        base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    )
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


# ─────────────────────────────────────────────────────────────────────────────
# MCP helper  – open a session, run a coroutine, close cleanly
# ─────────────────────────────────────────────────────────────────────────────
async def _with_mcp_session(token: str, coro_fn):
    """
    Open an MCP ClientSession over the configured transport, call `coro_fn(session)`,
    return the result.  Both SSE and Streamable-HTTP transports are supported.
    """
    headers = {"Authorization": f"Bearer {token}"}

    if MCP_TRANSPORT == "streamable_http":
        if not _HAS_STREAMABLE_HTTP:
            raise RuntimeError(
                "streamable_http transport requires mcp >= 1.2. "
                "Set MCP_TRANSPORT=sse or upgrade the mcp package."
            )
        async with streamablehttp_client(MCP_SERVER_URL, headers=headers) as (
            read,
            write,
            _,
        ):
            async with ClientSession(read, write) as session:
                # Handshake: client sends `initialize`, server responds with capabilities
                await session.initialize()
                return await coro_fn(session)
    else:
        # Default: SSE transport (legacy MCP spec)
        async with sse_client(MCP_SERVER_URL, headers=headers) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await coro_fn(session)


# ─────────────────────────────────────────────────────────────────────────────
# UI routes
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "authenticated": bool(request.session.get("access_token")),
            "user_email": request.session.get("user_email", ""),
            "mcp_server_url": MCP_SERVER_URL,
            "mcp_transport": MCP_TRANSPORT,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# OAuth 2.1 Authorization Code Flow  (with PKCE)
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/login")
async def login(request: Request):
    """
    Step 1 – Build the authorization URL and redirect the browser there.

    We generate a random `state` value (anti-CSRF) and a PKCE pair.
    Both are saved in the server-side session so we can verify them in /callback.
    """
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)

    # Persist PKCE verifier and state; they are validated in /callback
    request.session["pkce_verifier"] = verifier
    request.session["oauth_state"] = state

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": OAUTH_SCOPE,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return RedirectResponse(f"{OAUTH_AUTH_URL}?{urlencode(params)}")


@app.get("/callback")
async def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
):
    """
    Step 2 – The OAuth provider redirects here with an authorization code.

    We validate `state` (anti-CSRF), then POST to the token endpoint with:
      - The authorization code
      - The PKCE code_verifier (proves this request originated the login)
      - client credentials (if the client is confidential)
    """
    if error:
        msg = error_description or error
        return HTMLResponse(
            f"<h2 style='font-family:sans-serif'>OAuth Error: {msg}</h2>"
            "<a href='/'>← Back</a>",
            status_code=400,
        )

    # CSRF check
    if not state or state != request.session.pop("oauth_state", None):
        return HTMLResponse(
            "<h2 style='font-family:sans-serif'>Invalid state — possible CSRF</h2>",
            status_code=400,
        )

    verifier = request.session.pop("pkce_verifier", None)
    if not verifier:
        return HTMLResponse(
            "<h2 style='font-family:sans-serif'>Missing PKCE verifier</h2>",
            status_code=400,
        )

    # Exchange the code for tokens
    payload: dict[str, Any] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
    }
    # Only include client_secret for confidential clients
    if CLIENT_SECRET:
        payload["client_secret"] = CLIENT_SECRET

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            OAUTH_TOKEN_URL,
            data=payload,
            headers={"Accept": "application/json"},
        )

    if resp.status_code != 200:
        return HTMLResponse(
            f"<h2 style='font-family:sans-serif'>Token exchange failed "
            f"({resp.status_code})</h2><pre>{resp.text}</pre><a href='/'>← Back</a>",
            status_code=400,
        )

    tokens = resp.json()
    request.session["access_token"] = tokens.get("access_token")
    request.session["refresh_token"] = tokens.get("refresh_token", "")

    # Optionally decode the id_token to show the user's email in the UI
    id_token = tokens.get("id_token", "")
    if id_token:
        try:
            # JWT payload is the second base64url segment (no signature verification here)
            payload_b64 = id_token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_b64))
            request.session["user_email"] = claims.get("email", "")
        except Exception:
            pass

    return RedirectResponse("/")


@app.get("/logout")
async def logout(request: Request):
    """Clear the session (drops the access token)."""
    request.session.clear()
    return RedirectResponse("/")


# ─────────────────────────────────────────────────────────────────────────────
# MCP API routes  (called by the browser via fetch())
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/tools")
async def api_list_tools(request: Request):
    """
    Connect to the MCP Server, send `tools/list`, return the tool catalogue.

    Each tool has: name, description, inputSchema (JSON Schema object).
    """
    token = request.session.get("access_token")
    if not token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    async def _list(session: ClientSession):
        result = await session.list_tools()
        return [
            {
                "name": t.name,
                "description": t.description or "",
                "inputSchema": t.inputSchema if isinstance(t.inputSchema, dict) else {},
            }
            for t in result.tools
        ]

    try:
        tools = await _with_mcp_session(token, _list)
        return JSONResponse({"tools": tools})
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@app.post("/api/call-tool")
async def api_call_tool(request: Request):
    """
    Connect to the MCP Server, send `tools/call` with the requested tool name
    and arguments.  Returns the content array from the tool result.
    """
    token = request.session.get("access_token")
    if not token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Request body must be JSON"}, status_code=400)

    tool_name: str = body.get("tool_name", "").strip()
    arguments: dict = body.get("arguments", {})

    if not tool_name:
        return JSONResponse({"error": "tool_name is required"}, status_code=400)

    async def _call(session: ClientSession):
        result = await session.call_tool(tool_name, arguments=arguments)
        # Serialize content items to plain dicts
        content = []
        for item in result.content:
            if hasattr(item, "text"):
                content.append({"type": "text", "text": item.text})
            elif hasattr(item, "data"):
                content.append({"type": getattr(item, "type", "blob"), "data": item.data})
            else:
                content.append({"type": "unknown", "raw": str(item)})
        return {"content": content, "isError": bool(result.isError)}

    try:
        result = await _with_mcp_session(token, _call)
        return JSONResponse(result)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


# ─────────────────────────────────────────────────────────────────────────────
# Health check
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "mcp_server": MCP_SERVER_URL, "transport": MCP_TRANSPORT}


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

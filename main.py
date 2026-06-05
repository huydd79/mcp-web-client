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
import logging
import os
import secrets
import traceback
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.shared.exceptions import McpError
from starlette.middleware.sessions import SessionMiddleware

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("mcp-web-client")

# ── Streamable HTTP transport (MCP spec ≥ 2025-11-05) ────────────────────────
try:
    from mcp.client.streamable_http import streamablehttp_client

    _HAS_STREAMABLE_HTTP = True
except ImportError:
    _HAS_STREAMABLE_HTTP = False
    log.warning("streamable_http transport not available (need mcp>=1.2)")

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

# ─────────────────────────────────────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="MCP Web Client", docs_url="/docs")

# Session middleware stores OAuth tokens server-side in signed cookies.
# max_age=3600 → sessions expire after 1 hour.
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=3600)

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
# MCP OAuth Discovery helpers
# Per MCP spec, each MCP server exposes its own OAuth authority at
# {server_url}/.well-known/oauth-authorization-server
# ─────────────────────────────────────────────────────────────────────────────
async def _discover_mcp_oauth(mcp_url: str) -> dict:
    """
    Fetch OAuth metadata from the MCP server's well-known discovery endpoint.
    Returns the raw metadata dict, or {} on failure.
    """
    parsed = urlparse(mcp_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    # Try full-path discovery first (MCP Gateway style: each server has its own issuer at the path)
    # then fall back to origin-only (mcp-pvwa style: discovery always at root)
    candidates = [
        mcp_url.rstrip("/") + "/.well-known/oauth-authorization-server",
        origin + "/.well-known/oauth-authorization-server",
    ]
    # Deduplicate (happens when URL has no path)
    seen: set[str] = set()
    candidates = [u for u in candidates if not (u in seen or seen.add(u))]

    try:
        async with httpx.AsyncClient(timeout=8.0) as http:
            for url in candidates:
                log.debug("OAuth discovery: GET %s", url)
                try:
                    r = await http.get(url)
                    if r.status_code == 200:
                        data = r.json()
                        log.info("OAuth discovery OK at %s — issuer=%s auth=%s",
                                 url, data.get("issuer"), data.get("authorization_endpoint"))
                        return data
                    log.debug("OAuth discovery %s returned %s", url, r.status_code)
                except Exception as exc:
                    log.debug("OAuth discovery %s failed: %s", url, exc)
    except Exception as exc:
        log.debug("OAuth discovery client error: %s", exc)
    return {}


async def _register_dynamic_client(registration_url: str) -> str | None:
    """
    Register a public OAuth client via RFC 7591 Dynamic Client Registration.
    Returns the assigned client_id, or None on failure.
    Public client = no client_secret, token_endpoint_auth_method=none.
    """
    try:
        async with httpx.AsyncClient(timeout=8.0) as http:
            r = await http.post(registration_url, json={
                "redirect_uris": [REDIRECT_URI],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            })
            if r.status_code in (200, 201):
                cid = r.json().get("client_id")
                log.info("Dynamic client registered: %s", cid)
                return cid
            log.warning("Dynamic registration failed %s: %s", r.status_code, r.text[:300])
    except Exception as exc:
        log.warning("Dynamic registration error: %s", exc)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Session config helpers – URL/transport can be overridden via GUI at runtime
# ─────────────────────────────────────────────────────────────────────────────
def _sess_url(request: Request) -> str:
    return request.session.get("mcp_server_url", MCP_SERVER_URL)

def _sess_transport(request: Request) -> str:
    return request.session.get("mcp_transport", MCP_TRANSPORT)


# ─────────────────────────────────────────────────────────────────────────────
# MCP helper  – open a session, run a coroutine, close cleanly
# ─────────────────────────────────────────────────────────────────────────────
async def _with_mcp_session(token: str, coro_fn, *,
                             mcp_url: str | None = None,
                             mcp_transport: str | None = None):
    """
    Open an MCP ClientSession over the configured transport, call `coro_fn(session)`,
    return the result.  URL and transport can be overridden per-request (GUI config).
    """
    url = mcp_url or MCP_SERVER_URL
    transport = mcp_transport or MCP_TRANSPORT
    headers = {"Authorization": f"Bearer {token}"}

    if transport == "streamable_http":
        if not _HAS_STREAMABLE_HTTP:
            raise RuntimeError(
                "streamable_http transport requires mcp >= 1.2. "
                "Set MCP_TRANSPORT=sse or upgrade the mcp package."
            )
        log.info("Connecting to MCP server via streamable_http: %s", url)
        try:
            async with streamablehttp_client(url, headers=headers) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await coro_fn(session)
        except* Exception as eg:
            for exc in eg.exceptions:
                if isinstance(exc, httpx.HTTPStatusError):
                    log.warning("MCP transport error: %s %s", exc.response.status_code, exc.request.url)
                else:
                    log.error("TaskGroup sub-exception: %s", exc, exc_info=True)
            raise
    else:
        log.info("Connecting to MCP server via SSE: %s", url)
        async with sse_client(url, headers=headers) as (read, write):
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
            "mcp_server_url": _sess_url(request),
            "mcp_transport": _sess_transport(request),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# OAuth 2.1 Authorization Code Flow  (with PKCE)
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/login")
async def login(request: Request):
    """
    Step 1 – Discover OAuth endpoints from the MCP server, register a dynamic
    client if needed, then redirect the browser to the authorization URL.

    Discovery priority:
      1. GET {MCP_SERVER_URL}/.well-known/oauth-authorization-server
      2. Fall back to OAUTH_AUTH_URL / OAUTH_TOKEN_URL env vars

    Client priority:
      1. Dynamic registration via discovered registration_endpoint (public client)
      2. Configured CLIENT_ID (confidential client with CLIENT_SECRET)
    """
    # ── Step 0: discover OAuth endpoints from the MCP server ──────────────────
    disc = await _discover_mcp_oauth(_sess_url(request))
    auth_url  = disc.get("authorization_endpoint") or OAUTH_AUTH_URL
    token_url = disc.get("token_endpoint")         or OAUTH_TOKEN_URL
    reg_url   = disc.get("registration_endpoint")

    # ── Step 0b: dynamic client registration (public, no secret) ──────────────
    # Register fresh each login so we always have a valid client_id for this server.
    dynamic_client_id: str | None = None
    if reg_url:
        dynamic_client_id = await _register_dynamic_client(reg_url)

    # Pick the client_id to use: dynamic > configured
    client_id = dynamic_client_id or CLIENT_ID
    # Public dynamic client never sends a secret
    use_secret = (dynamic_client_id is None) and bool(CLIENT_SECRET)

    # ── Store resolved values in session so /callback can use them ─────────────
    request.session["_token_url"]  = token_url
    request.session["_client_id"]  = client_id
    request.session["_use_secret"] = use_secret
    request.session["_disc_auth"]  = auth_url   # for debug

    # ── Filter scope against server's supported list ───────────────────────────
    supported = disc.get("scopes_supported")
    if supported:
        scope = " ".join(s for s in OAUTH_SCOPE.split() if s in supported) or OAUTH_SCOPE
    else:
        scope = OAUTH_SCOPE
    log.info("Login: auth=%s token=%s client=%s dynamic=%s scope=%s",
             auth_url, token_url, client_id, bool(dynamic_client_id), scope)

    # ── PKCE + state ───────────────────────────────────────────────────────────
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)
    request.session["pkce_verifier"] = verifier
    request.session["oauth_state"]   = state

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return RedirectResponse(f"{auth_url}?{urlencode(params)}")


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

    # Retrieve discovered/registered values stored by /login
    token_url = request.session.pop("_token_url",  OAUTH_TOKEN_URL)
    client_id = request.session.pop("_client_id",  CLIENT_ID)
    use_secret = request.session.pop("_use_secret", bool(CLIENT_SECRET))

    log.info("Callback: exchanging code at %s with client=%s", token_url, client_id)

    # Exchange the code for tokens
    payload: dict[str, Any] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
        "code_verifier": verifier,
    }
    # Only include client_secret for confidential clients (not dynamic public clients)
    if use_secret:
        payload["client_secret"] = CLIENT_SECRET

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            token_url,
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
def _extract_error(exc: Exception) -> str:
    """Unwrap ExceptionGroup/TaskGroup errors to get the real cause."""
    if isinstance(exc, ExceptionGroup):
        causes = [_extract_error(e) for e in exc.exceptions]
        return "; ".join(causes)
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        hint = ""
        if status == 405:
            hint = " — try switching transport (sse ↔ streamable_http)"
        elif status == 401:
            hint = " — token may be expired, try logging in again"
        elif status == 403:
            hint = " — insufficient permissions for this MCP server"
        return f"MCP server returned {status} {exc.response.reason_phrase}{hint}"
    return str(exc) or type(exc).__name__


def _http_status_for(exc: Exception) -> int:
    """Return an appropriate HTTP status code for the given exception."""
    if isinstance(exc, ExceptionGroup):
        for e in exc.exceptions:
            code = _http_status_for(e)
            if code != 500:
                return code
    if isinstance(exc, httpx.HTTPStatusError):
        return 502
    return 500


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
        tools = await _with_mcp_session(token, _list, mcp_url=_sess_url(request), mcp_transport=_sess_transport(request))
        return JSONResponse({"tools": tools})
    except Exception as exc:
        log.error("api_list_tools failed", exc_info=True) if _http_status_for(exc) == 500 else log.warning("api_list_tools: %s", _extract_error(exc))
        return JSONResponse({"error": _extract_error(exc)}, status_code=_http_status_for(exc))


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
        result = await _with_mcp_session(token, _call, mcp_url=_sess_url(request), mcp_transport=_sess_transport(request))
        return JSONResponse(result)
    except Exception as exc:
        log.error("api_call_tool failed", exc_info=True) if _http_status_for(exc) == 500 else log.warning("api_call_tool: %s", _extract_error(exc))
        return JSONResponse({"error": _extract_error(exc)}, status_code=_http_status_for(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Prompts API routes
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/prompts")
async def api_list_prompts(request: Request):
    """Connect to the MCP Server, send `prompts/list`, return the prompt catalogue."""
    token = request.session.get("access_token")
    if not token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    async def _list(session: ClientSession):
        try:
            result = await session.list_prompts()
        except McpError as e:
            log.info("Server does not support prompts/list: %s", e)
            return []
        return [
            {
                "name": p.name,
                "description": p.description or "",
                "arguments": [
                    {
                        "name": a.name,
                        "description": a.description or "",
                        "required": bool(a.required),
                    }
                    for a in (p.arguments or [])
                ],
            }
            for p in result.prompts
        ]

    try:
        prompts = await _with_mcp_session(token, _list, mcp_url=_sess_url(request), mcp_transport=_sess_transport(request))
        return JSONResponse({"prompts": prompts})
    except Exception as exc:
        log.error("api_list_prompts failed", exc_info=True) if _http_status_for(exc) == 500 else log.warning("api_list_prompts: %s", _extract_error(exc))
        return JSONResponse({"error": _extract_error(exc)}, status_code=_http_status_for(exc))


@app.post("/api/get-prompt")
async def api_get_prompt(request: Request):
    """Send `prompts/get` with a prompt name and string arguments."""
    token = request.session.get("access_token")
    if not token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Request body must be JSON"}, status_code=400)

    prompt_name: str = body.get("prompt_name", "").strip()
    # Prompt arguments are always string-valued per MCP spec
    arguments: dict[str, str] = {k: str(v) for k, v in body.get("arguments", {}).items()}

    if not prompt_name:
        return JSONResponse({"error": "prompt_name is required"}, status_code=400)

    async def _get(session: ClientSession):
        result = await session.get_prompt(prompt_name, arguments=arguments or None)
        messages = []
        for msg in (result.messages or []):
            c = msg.content
            if hasattr(c, "text"):
                messages.append({"role": str(msg.role), "type": "text", "text": c.text})
            elif hasattr(c, "blob"):
                messages.append({"role": str(msg.role), "type": "blob", "blob": c.blob,
                                  "mimeType": getattr(c, "mimeType", "") or ""})
            else:
                messages.append({"role": str(msg.role), "type": "unknown", "raw": str(c)})
        return {"description": result.description or "", "messages": messages}

    try:
        result = await _with_mcp_session(token, _get, mcp_url=_sess_url(request), mcp_transport=_sess_transport(request))
        return JSONResponse(result)
    except Exception as exc:
        log.error("api_get_prompt failed", exc_info=True) if _http_status_for(exc) == 500 else log.warning("api_get_prompt: %s", _extract_error(exc))
        return JSONResponse({"error": _extract_error(exc)}, status_code=_http_status_for(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Resources API routes
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/resources")
async def api_list_resources(request: Request):
    """Connect to the MCP Server, send `resources/list`, return the resource catalogue."""
    token = request.session.get("access_token")
    if not token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    async def _list(session: ClientSession):
        try:
            result = await session.list_resources()
        except McpError as e:
            log.info("Server does not support resources/list: %s", e)
            return []
        return [
            {
                "uri": str(r.uri),
                "name": r.name or "",
                "description": r.description or "",
                "mimeType": r.mimeType or "",
            }
            for r in result.resources
        ]

    try:
        resources = await _with_mcp_session(token, _list, mcp_url=_sess_url(request), mcp_transport=_sess_transport(request))
        return JSONResponse({"resources": resources})
    except Exception as exc:
        log.error("api_list_resources failed", exc_info=True) if _http_status_for(exc) == 500 else log.warning("api_list_resources: %s", _extract_error(exc))
        return JSONResponse({"error": _extract_error(exc)}, status_code=_http_status_for(exc))


@app.post("/api/read-resource")
async def api_read_resource(request: Request):
    """Send `resources/read` with a resource URI."""
    token = request.session.get("access_token")
    if not token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Request body must be JSON"}, status_code=400)

    uri: str = body.get("uri", "").strip()
    if not uri:
        return JSONResponse({"error": "uri is required"}, status_code=400)

    async def _read(session: ClientSession):
        result = await session.read_resource(uri)  # type: ignore[arg-type]
        contents = []
        for item in (result.contents or []):
            if hasattr(item, "text"):
                contents.append({
                    "type": "text", "uri": str(item.uri),
                    "text": item.text, "mimeType": getattr(item, "mimeType", "") or "",
                })
            elif hasattr(item, "blob"):
                contents.append({
                    "type": "blob", "uri": str(item.uri),
                    "blob": item.blob, "mimeType": getattr(item, "mimeType", "") or "",
                })
            else:
                contents.append({"type": "unknown", "uri": str(item.uri), "raw": str(item)})
        return {"contents": contents}

    try:
        result = await _with_mcp_session(token, _read, mcp_url=_sess_url(request), mcp_transport=_sess_transport(request))
        return JSONResponse(result)
    except Exception as exc:
        log.error("api_read_resource failed", exc_info=True) if _http_status_for(exc) == 500 else log.warning("api_read_resource: %s", _extract_error(exc))
        return JSONResponse({"error": _extract_error(exc)}, status_code=_http_status_for(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Runtime config – allow GUI to override MCP server URL and transport
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/config")
async def get_config(request: Request):
    return JSONResponse({
        "mcp_server_url": _sess_url(request),
        "mcp_transport": _sess_transport(request),
    })


@app.post("/api/config")
async def update_config(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Request body must be JSON"}, status_code=400)

    new_url = body.get("mcp_server_url", "").strip()
    new_transport = body.get("mcp_transport", "").strip()

    old_url = _sess_url(request)
    url_changed = bool(new_url) and new_url != old_url

    if new_url:
        request.session["mcp_server_url"] = new_url
    if new_transport in ("sse", "streamable_http"):
        request.session["mcp_transport"] = new_transport

    # Different server → invalidate the current token (it's bound to the old server's OAuth)
    if url_changed:
        request.session.pop("access_token", None)
        request.session.pop("refresh_token", None)
        request.session.pop("user_email", None)
        log.info("MCP server changed to %s — session auth cleared", new_url)

    return JSONResponse({
        "mcp_server_url": _sess_url(request),
        "mcp_transport": _sess_transport(request),
        "auth_cleared": url_changed,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Debug endpoints
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/api/debug/discovery")
async def debug_discovery():
    """Fetch and return the MCP server's OAuth discovery metadata."""
    disc = await _discover_mcp_oauth(MCP_SERVER_URL)
    return JSONResponse({
        "mcp_server_url": MCP_SERVER_URL,
        "discovery_url": MCP_SERVER_URL.rstrip("/") + "/.well-known/oauth-authorization-server",
        "discovered": disc,
        "env_fallback": {
            "OAUTH_AUTH_URL": OAUTH_AUTH_URL,
            "OAUTH_TOKEN_URL": OAUTH_TOKEN_URL,
            "CLIENT_ID": CLIENT_ID[:8] + "…" if len(CLIENT_ID) > 8 else CLIENT_ID,
        },
    })


@app.get("/api/debug/token")
async def debug_token(request: Request):
    """Show JWT claims from the current session token (no sig verification)."""
    token = request.session.get("access_token")
    if not token:
        return JSONResponse({"error": "No access_token in session"}, status_code=401)

    result: dict[str, Any] = {
        "token_prefix": token[:20] + "…",
        "token_length": len(token),
        "mcp_server_url": MCP_SERVER_URL,
        "mcp_transport": MCP_TRANSPORT,
    }

    # Decode each JWT segment (access_token may be opaque if not a JWT)
    parts = token.split(".")
    if len(parts) == 3:
        for name, segment in [("header", parts[0]), ("payload", parts[1])]:
            try:
                padded = segment + "=" * (-len(segment) % 4)
                result[name] = json.loads(base64.urlsafe_b64decode(padded))
            except Exception as e:
                result[name] = f"decode error: {e}"
    else:
        result["note"] = "Token is not a JWT (opaque token)"

    return JSONResponse(result)


# ─────────────────────────────────────────────────────────────────────────────
# Health check
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "mcp_server": MCP_SERVER_URL, "transport": MCP_TRANSPORT}


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

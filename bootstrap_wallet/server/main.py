'''Clean FastAPI server for the Sats‑Stack wallet.

- Provides node‑manager endpoints (list/start/stop/status).
- Provides transaction endpoints for multiple chains via ``bootstrap_wall3t.wallet.tx_routes``.
- Includes CORS, HTTPS‑redirect (no‑op in dev), simple rate‑limiting and a very
  lightweight token/JWT auth (same as before).

All heavy crypto logic lives in the chain providers; this file only wires the
HTTP layer.
'''

from __future__ import annotations

import os
import json
import time
import base64
import hmac
import hashlib
import math
from typing import List, Dict, Any

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# ---------------------------------------------------------------------------
# Middleware – rate limiting and CORS
# ---------------------------------------------------------------------------

class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 10, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window_seconds
        self.ip_history: dict[str, List[float]] = {}

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        timestamps = self.ip_history.get(client_ip, [])
        timestamps = [t for t in timestamps if now - t < self.window]
        timestamps.append(now)
        self.ip_history[client_ip] = timestamps
        if len(timestamps) > self.max_requests:
            return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
        return await call_next(request)

# ---------------------------------------------------------------------------
# App creation and global config
# ---------------------------------------------------------------------------

app = FastAPI()
app.state.tx_signer = None


def configure_tx_signer(signer: Any) -> None:
    """Inject a vault-backed signer after the operator unlock ceremony."""
    if signer is None or not callable(getattr(signer, "sign", None)):
        raise TypeError("signer must provide a callable sign method")
    app.state.tx_signer = signer

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "chrome-extension://*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(RateLimiterMiddleware, max_requests=10, window_seconds=60)


def _required_secret(name: str) -> str:
    """Load a high-entropy deployment secret or fail closed at startup."""
    value = os.getenv(name)
    if not value or len(value) < 32:
        raise RuntimeError(f'{name} must be set to a secret of at least 32 characters')
    return value


def _required_setting(name: str) -> str:
    """Load a non-secret security setting or fail closed at startup."""
    value = os.getenv(name)
    if not value or len(value) > 256:
        raise RuntimeError(f'{name} must be configured and no longer than 256 characters')
    return value


DEV_TOKEN = _required_secret("DEV_TOKEN")
JWT_SECRET = _required_secret("JWT_SECRET")
if DEV_TOKEN == JWT_SECRET:
    raise RuntimeError('DEV_TOKEN and JWT_SECRET must be distinct secrets')
JWT_ISSUER = _required_setting("JWT_ISSUER")
JWT_AUDIENCE = _required_setting("JWT_AUDIENCE")
JWT_CLOCK_SKEW_SECONDS = 30
JWT_MAX_LIFETIME_SECONDS = 900

def _decode_jwt(token: str) -> dict:
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
        def pad(b: str) -> str:
            return b + '=' * (-len(b) % 4)
        header = json.loads(base64.urlsafe_b64decode(pad(header_b64)))
        if not isinstance(header, dict) or header.get('alg') != 'HS256' or header.get('typ') != 'JWT':
            raise ValueError('Unsupported JWT header')
        payload = json.loads(base64.urlsafe_b64decode(pad(payload_b64)))
        if not isinstance(payload, dict):
            raise ValueError('Invalid JWT claims')
        signed = f"{header_b64}.{payload_b64}".encode()
        expected_sig = hmac.new(JWT_SECRET.encode(), signed, hashlib.sha256).digest()
        actual_sig = base64.urlsafe_b64decode(pad(signature_b64))
        if not hmac.compare_digest(expected_sig, actual_sig):
            raise ValueError("Invalid signature")

        principal = payload.get('sub')
        issuer = payload.get('iss')
        audience = payload.get('aud')
        now = time.time()
        if not isinstance(principal, str) or not principal or len(principal) > 128:
            raise ValueError('Invalid subject')
        if issuer != JWT_ISSUER:
            raise ValueError('Invalid issuer')
        if isinstance(audience, str):
            audience_values = [audience]
        elif isinstance(audience, list) and all(isinstance(item, str) for item in audience):
            audience_values = audience
        else:
            raise ValueError('Invalid audience')
        if JWT_AUDIENCE not in audience_values:
            raise ValueError('Invalid audience')

        exp = payload.get('exp')
        issued_at = payload.get('iat')
        not_before = payload.get('nbf', issued_at)
        numeric_claims = (exp, issued_at, not_before)
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            for value in numeric_claims
        ):
            raise ValueError('Invalid JWT time claims')
        if exp <= now - JWT_CLOCK_SKEW_SECONDS:
            raise ValueError('JWT expired')
        if issued_at > now + JWT_CLOCK_SKEW_SECONDS:
            raise ValueError('JWT issued in the future')
        if not_before > now + JWT_CLOCK_SKEW_SECONDS:
            raise ValueError('JWT not yet valid')
        if exp <= issued_at or exp - issued_at > JWT_MAX_LIFETIME_SECONDS:
            raise ValueError('JWT lifetime is invalid')
        return payload
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid JWT")

def _require_auth(request: Request) -> None:
    auth = request.headers.get('Authorization')
    if not auth or not auth.startswith('Bearer '):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Missing token')
    token = auth.removeprefix('Bearer ').strip()
    if token == DEV_TOKEN:
        return
    _decode_jwt(token)

# ---------------------------------------------------------------------------
# Node manager routes (simple passthrough to the existing manager)
# ---------------------------------------------------------------------------

from node_manager import manager as node_mgr

@app.get("/nodes")
async def get_nodes(request: Request):
    _require_auth(request)
    return node_mgr.list_nodes()

@app.post("/nodes/{name}/start")
async def start_node(name: str, request: Request):
    _require_auth(request)
    return node_mgr.start_node(name)

@app.post("/nodes/{name}/stop")
async def stop_node(name: str, request: Request):
    _require_auth(request)
    return node_mgr.stop_node(name)

@app.get("/nodes/{name}/status")
async def node_status(name: str, request: Request):
    _require_auth(request)
    return node_mgr.node_status(name)

# ---------------------------------------------------------------------------
# Elixir proxy (unchanged)
# ---------------------------------------------------------------------------

import httpx
ELIXIR_URL = "http://127.0.0.1:4000"

@app.post("/elixir/agents/start/{name}")
async def elixir_start_agent(name: str, request: Request):
    _require_auth(request)
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{ELIXIR_URL}/agents/start/{name}")
    return {"status": resp.status_code, "detail": resp.text}

@app.post("/elixir/agents/stop/{name}")
async def elixir_stop_agent(name: str, request: Request):
    _require_auth(request)
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{ELIXIR_URL}/agents/stop/{name}")
    return {"status": resp.status_code, "detail": resp.text}

@app.get("/elixir/agents/status/{name}")
async def elixir_status_agent(name: str, request: Request):
    _require_auth(request)
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{ELIXIR_URL}/agents/status/{name}")
    return {"status": resp.status_code, "detail": resp.text}

# ---------------------------------------------------------------------------
# Mock data models (unchanged from original)
# ---------------------------------------------------------------------------

from pydantic import BaseModel
import datetime

class VaultResponse(BaseModel):
    balance: int = 0

class Tx(BaseModel):
    id: str
    amount: int
    timestamp: str

class AutomationPolicy(BaseModel):
    name: str
    description: str | None = None

MOCK_VAULT = VaultResponse(balance=0)
MOCK_HISTORY = [
    Tx(id="tx1", amount=2500, timestamp=str(datetime.datetime.utcnow())),
    Tx(id="tx2", amount=1200, timestamp=str(datetime.datetime.utcnow())),
]
MOCK_AUTOMATIONS = [
    AutomationPolicy(name="FaucetCollector", description="Collect from known faucets every hour"),
    AutomationPolicy(name="GameFiScout", description="Monitor GameFi reward APIs"),
]

@app.get("/vault", response_model=VaultResponse)
async def get_vault(request: Request):
    _require_auth(request)
    return MOCK_VAULT

@app.get("/history", response_model=List[Tx])
async def get_history(request: Request):
    _require_auth(request)
    return MOCK_HISTORY

# ---------------------------------------------------------------------------
# Transaction routes (multi‑chain) – imported from wallet package
# ---------------------------------------------------------------------------

from bootstrap_wall3t.wallet.tx_routes import router as tx_router
app.include_router(tx_router, prefix="/tx")

# ---------------------------------------------------------------------------
# Simple placeholder Lightning payment endpoint (unchanged)
# ---------------------------------------------------------------------------

@app.post("/pay")
async def post_pay(payload: dict, request: Request):
    _require_auth(request)
    return {"status": "mock", "received": payload}

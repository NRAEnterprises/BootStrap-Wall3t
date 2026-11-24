'''Transaction API routes – multi‑chain support.

The router delegates all work to the appropriate ``ChainProvider`` from
``bootstrap_wall3t.chain.registry``.  The flow is:

1. ``POST /tx/{chain}/create`` – build an unsigned transaction dict.
2. ``POST /tx/{chain}/sign``   – sign through an injected vault-backed signer.
3. ``POST /tx/{chain}/broadcast`` – mock‑broadcast the signed transaction and
   return a fake tx‑id.

All endpoints require the ``Authorization: Bearer <token>`` header that the
existing server middleware validates.
'''

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from typing import Any, Dict
from bootstrap_wall3t.chain.registry import get_provider
from bootstrap_wall3t.wallet.vault_signer import SigningUnavailable

router = APIRouter()


class TxCreateRequest(BaseModel):
    params: Dict[str, Any]

class TxSignRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    unsigned_tx: Dict[str, Any]

class TxBroadcastRequest(BaseModel):
    signed_tx: Dict[str, Any]


def _jwt_principal(token: str) -> str:
    secret = os.getenv('JWT_SECRET')
    if not secret or len(secret) < 32:
        raise HTTPException(status_code=503, detail='Authentication is not configured securely')
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
        padding = lambda value: value + '=' * (-len(value) % 4)
        header = json.loads(base64.urlsafe_b64decode(padding(header_b64)))
        if not isinstance(header, dict) or header.get('alg') != 'HS256':
            raise ValueError
        payload = json.loads(base64.urlsafe_b64decode(padding(payload_b64)))
        if not isinstance(payload, dict):
            raise ValueError
        signed = f'{header_b64}.{payload_b64}'.encode()
        expected = hmac.new(secret.encode(), signed, hashlib.sha256).digest()
        actual = base64.urlsafe_b64decode(padding(signature_b64))
        if not hmac.compare_digest(expected, actual):
            raise ValueError
        principal = payload.get('sub')
        if not isinstance(principal, str) or not principal or len(principal) > 128:
            raise ValueError
        return principal
    except (
        ValueError,
        TypeError,
        KeyError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        binascii.Error,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid authenticated principal',
        ) from exc


def _require_auth(request: Request) -> str | None:
    # Keep this router fail-closed when mounted independently from the main app.
    auth = request.headers.get('Authorization')
    if not auth or not auth.startswith('Bearer '):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Missing token')
    token = auth.removeprefix('Bearer ').strip()
    configured_token = os.getenv('DEV_TOKEN')
    if not configured_token or len(configured_token) < 32:
        raise HTTPException(status_code=503, detail='Authentication is not configured securely')
    if hmac.compare_digest(token, configured_token):
        principal = os.getenv('DEV_TOKEN_AGENT_ID')
        request.state.principal = principal
        return principal
    principal = _jwt_principal(token)
    request.state.principal = principal
    return principal


@router.post('/{chain}/create', response_model=Dict[str, Any])
async def create_tx(chain: str, request: Request, body: TxCreateRequest):
    _require_auth(request)
    try:
        provider = get_provider(chain)
    except KeyError:
        raise HTTPException(status_code=404, detail=f'Chain {chain!r} not supported')
    try:
        unsigned = provider.build_tx(body.params)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return unsigned


@router.post('/{chain}/sign', response_model=Dict[str, Any])
async def sign_tx(chain: str, request: Request, body: TxSignRequest):
    principal = _require_auth(request)
    if not principal:
        raise HTTPException(status_code=403, detail='Authenticated principal is not authorized for signing')
    signer = getattr(request.app.state, 'tx_signer', None)
    if signer is None:
        raise HTTPException(
            status_code=503,
            detail='Transaction signing is unavailable until a vault-backed signer is configured',
        )
    try:
        return signer.sign(chain, principal, body.unsigned_tx)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f'Chain {chain!r} not supported') from exc
    except SigningUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post('/{chain}/broadcast', response_model=Dict[str, str])
async def broadcast_tx(chain: str, request: Request, body: TxBroadcastRequest):
    _require_auth(request)
    try:
        provider = get_provider(chain)
    except KeyError:
        raise HTTPException(status_code=404, detail=f'Chain {chain!r} not supported')
    try:
        txid = provider.broadcast_tx(body.signed_tx)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"txid": txid}

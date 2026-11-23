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

import hmac
import os
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel
from typing import Any, Dict
from bootstrap_wall3t.chain.registry import get_provider
from bootstrap_wall3t.wallet.vault_signer import SigningUnavailable

router = APIRouter()


class TxCreateRequest(BaseModel):
    params: Dict[str, Any]

class TxSignRequest(BaseModel):
    unsigned_tx: Dict[str, Any]
    agent_id: str

class TxBroadcastRequest(BaseModel):
    signed_tx: Dict[str, Any]


def _require_auth(request: Request):
    # Keep this router fail-closed when mounted independently from the main app.
    auth = request.headers.get('Authorization')
    if not auth or not auth.startswith('Bearer '):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Missing token')
    token = auth.removeprefix('Bearer ').strip()
    configured_token = os.getenv('DEV_TOKEN')
    if not configured_token or len(configured_token) < 32:
        raise HTTPException(status_code=503, detail='Authentication is not configured securely')
    if not hmac.compare_digest(token, configured_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')


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
    _require_auth(request)
    signer = getattr(request.app.state, 'tx_signer', None)
    if signer is None:
        raise HTTPException(
            status_code=503,
            detail='Transaction signing is unavailable until a vault-backed signer is configured',
        )
    try:
        return signer.sign(chain, body.agent_id, body.unsigned_tx)
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

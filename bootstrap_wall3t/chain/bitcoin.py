# Bitcoin (BTC) placeholder provider.

"""This implementation is deliberately simple – it does **not** talk to a real
Bitcoin node.  It derives a deterministic private key from a mnemonic, builds a
mock transaction dictionary, signs it with the HMAC‑SHA256 helper from the base
class, and returns a fake tx‑id.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

from .base import ChainProvider
from bootstrap_wall3t.wallet.key_manager import get_private_key


class BitcoinProvider(ChainProvider):
    """Placeholder provider for the Bitcoin network.

    The provider implements deterministic key derivation, a mock address
    generator, transaction construction, and a dummy broadcast method.
    """

    name = "Bitcoin"

    def __init__(self) -> None:
        self.chain = "bitcoin"

    def derive_key(self, mnemonic: str) -> bytes:
        """Derive a deterministic private key for Bitcoin.
        Uses the shared key manager helper with the chain label.
        """
        return get_private_key(mnemonic, self.chain)

    def get_address(self, mnemonic: str) -> str:
        """Return a mock Bitcoin address derived from the private key.
        The address is the first 30 characters of a SHA‑256 hash, prefixed with
        ``btc_``.
        """
        key = self.derive_key(mnemonic)
        digest = hashlib.sha256(key).hexdigest()
        return f"btc_{digest[:30]}"

    def build_tx(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Construct a minimal transaction dictionary.
        Expected keys: ``to``, ``amount`` (satoshis), ``fee`` (satoshis).
        Optional ``memo`` and ``nonce`` default to empty string and ``0``.
        """
        required = {"to", "amount", "fee"}
        missing = required - params.keys()
        if missing:
            raise ValueError(f"Missing required fields for Bitcoin tx: {missing}")
        tx: Dict[str, Any] = {
            "chain": self.chain,
            "type": "transfer",
            "to": params["to"],
            "amount": params["amount"],
            "fee": params["fee"],
            "memo": params.get("memo", ""),
            "nonce": params.get("nonce", 0),
        }
        return tx

    def broadcast_tx(self, signed_tx: Dict[str, Any]) -> str:
        """Simulate broadcasting a transaction and return a fake tx‑id.
        The tx‑id is derived from the SHA‑256 hash of the JSON payload.
        """
        payload = json.dumps(signed_tx, sort_keys=True).encode()
        txid = hashlib.sha256(payload).hexdigest()[:12]
        return f"0x{txid}"

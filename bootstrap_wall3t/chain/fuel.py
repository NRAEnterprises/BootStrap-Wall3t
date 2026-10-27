# Fuel (FuelVM) placeholder provider.

"""Fuel is a low‑cost, parallel‑execution L1 for the Sway language.
For our demo we reuse the generic EVM‑style deterministic key derivation and address scheme,
but expose a distinct chain identifier so callers can target it specifically.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

from .base import ChainProvider


class FuelProvider(ChainProvider):
    """Placeholder provider for the Fuel network.

    The implementation mirrors the EVM provider but uses a different address
    formatting ("fuel_" prefix) and a simplified transaction shape.
    """

    name = "Fuel"

    def __init__(self) -> None:
        self.chain = "fuel"

    def derive_key(self, mnemonic: str) -> str:
        """Derive a deterministic dummy private key string for Fuel.
        Returns a prefixed identifier based on a SHA‑256 hash of the mnemonic.
        """
        digest = hashlib.sha256(mnemonic.encode()).hexdigest()
        return f"fuel-key-{digest[:30]}"

    def get_address(self, key: str) -> str:
        """Return a dummy Fuel address derived from the provided key.
        The argument is expected to be the deterministic key string returned by
        :meth:`derive_key`. The address is the first 30 characters of a SHA‑256
        hash of that key, prefixed with ``fuel1``.
        """
        # Hash the supplied key string directly.
        digest = hashlib.sha256(key.encode()).hexdigest()
        return f"fuel1{digest[:30]}"

    def build_tx(self, **params: Any) -> Dict[str, Any]:
        """Construct a minimal transaction dictionary.
        Expected keys: ``sender``, ``to``, ``amount``, ``fee``.
        Optional ``nonce`` defaults to ``0``.
        """
        required = {"sender", "to", "amount", "fee"}
        missing = required - params.keys()
        if missing:
            raise ValueError(f"Missing required fields for Fuel tx: {missing}")
        tx: Dict[str, Any] = {
            "chain": self.chain,
            "type": "transfer",
            "sender": params["sender"],
            "to": params["to"],
            "amount": params["amount"],
            "fee": params["fee"],
            "nonce": params.get("nonce", 0),
        }
        return tx

    def broadcast_tx(self, signed_tx: Dict[str, Any]) -> str:
        """Simulate broadcasting a transaction.
        Returns a fake transaction hash derived from the payload.
        """
        payload = json.dumps(signed_tx, sort_keys=True).encode()
        txid = hashlib.sha256(payload).hexdigest()[:12]
        return f"0x{txid}"

# EVM‑compatible (Ethereum, Arbitrum, Base) placeholder provider.

"""The class works for any EVM chain by receiving a ``chain`` identifier at
initialisation. All cryptographic operations are deterministic HMAC‑SHA256
derivations; address generation is a simple keccak‑256 hash of the private key.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

from .base import ChainProvider
from bootstrap_wall3t.wallet.key_manager import get_private_key

# Tiny keccak fallback using hashlib.sha3_256 (compatible for our placeholder).
def _keccak256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


class EVMProvider(ChainProvider):
    """Placeholder provider for any EVM‑compatible chain (Ethereum, Arbitrum, Base)."""

    def __init__(self, chain: str) -> None:
        self.chain = chain.lower()
        # Human‑readable name, e.g. "Ethereum" or "Arbitrum".
        self.name = chain.title()

    def derive_key(self, mnemonic: str) -> bytes:
        """Derive a deterministic private key for the given chain."""
        return get_private_key(mnemonic, self.chain)

    def get_address(self, mnemonic: str) -> str:
        """Return a mock EVM address derived from the private key.
        The address is the last 20 bytes of a keccak‑256 hash, hex‑prefixed with ``0x``.
        """
        key = self.derive_key(mnemonic)
        digest = _keccak256(key)
        addr = digest[-20:].hex()
        return f"0x{addr}"

    def build_tx(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Construct a minimal transaction dictionary.
        Expected keys: ``to``, ``value`` (wei), ``gas``, ``gas_price``, ``nonce``.
        Optional ``data`` defaults to ``0x``.
        """
        required = {"to", "value", "gas", "gas_price", "nonce"}
        missing = required - params.keys()
        if missing:
            raise ValueError(f"Missing required fields for EVM tx: {missing}")
        tx: Dict[str, Any] = {
            "chain": self.chain,
            "type": "transfer",
            "to": params["to"],
            "value": params["value"],
            "gas": params["gas"],
            "gas_price": params["gas_price"],
            "nonce": params["nonce"],
            "data": params.get("data", "0x"),
        }
        return tx

    def broadcast_tx(self, signed_tx: Dict[str, Any]) -> str:
        """Simulate broadcasting a transaction and return a fake transaction ID."""
        payload = json.dumps(signed_tx, sort_keys=True).encode()
        txid = hashlib.sha256(payload).hexdigest()[:12]
        return f"0x{txid}"

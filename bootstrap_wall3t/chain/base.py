# Base class for chain‑specific wallet operations.

"""Each concrete provider implements deterministic key‑derivation, transaction
construction, signing and broadcasting. The implementation is deliberately
lightweight – it uses only the standard library and the existing
`bootstrap_wall3t.wallet.key_manager` utilities – so it can run in the sandbox
without external dependencies.
"""

from __future__ import annotations

import abc
import json
import hashlib
import hmac
from typing import Any, Dict

from bootstrap_wall3t.wallet.key_manager import get_private_key


class ChainProvider(abc.ABC):
    """Abstract interface that all chain providers must implement.

    Sub‑classes must provide concrete implementations for key derivation,
    address generation, transaction construction and broadcasting.
    """

    name: str  # human‑readable chain name (e.g. "Bitcoin")

    @abc.abstractmethod
    def derive_key(self, mnemonic: str) -> bytes:
        """Return a deterministic private key (bytes) for the given mnemonic."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_address(self, mnemonic: str) -> str:
        """Derive a placeholder address from the mnemonic.
        Real implementations will replace this with proper address generation logic.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def build_tx(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Create an *unsigned* transaction dict from caller‑supplied parameters."""
        raise NotImplementedError

    def sign_tx(self, unsigned_tx: Dict[str, Any], private_key: bytes) -> str:
        """Produce a dummy signature using HMAC‑SHA256.

        The signature is deterministic and suitable for mock broadcasting.
        """
        payload = json.dumps(unsigned_tx, sort_keys=True).encode()
        sig = hmac.new(private_key, payload, hashlib.sha256).hexdigest()
        return sig

    @abc.abstractmethod
    def broadcast_tx(self, signed_tx: Dict[str, Any]) -> str:
        """Mock broadcast – log the transaction and return a fake tx‑id."""
        raise NotImplementedError

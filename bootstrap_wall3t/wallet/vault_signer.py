"""Vault-backed transaction signing boundary.

This adapter deliberately does not unlock the vault, accept mnemonics, or
persist key material. A deployment must inject an already-unlocked vault
instance and store chain-specific signing keys as ``b64:<base64>`` values in
the vault's in-memory agent profile.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any, Dict, Protocol

from bootstrap_wall3t.chain.registry import get_provider


class SigningUnavailable(RuntimeError):
    """Raised when the vault or requested key profile is unavailable."""


class AgentKeyVault(Protocol):
    """Minimal vault contract required by the signer."""

    def get_agent_keys(self, agent_id: str) -> Dict[str, Any]:
        ...


class VaultBackedSigner:
    """Sign transactions using key material released from an unlocked vault."""

    minimum_key_bytes = 32

    def __init__(self, vault: AgentKeyVault):
        self._vault = vault

    @staticmethod
    def _key_name(chain: str) -> str:
        normalized = chain.strip().lower()
        if not normalized or any(
            char not in "abcdefghijklmnopqrstuvwxyz0123456789-_"
            for char in normalized
        ):
            raise SigningUnavailable("Invalid chain identifier")
        return f"{normalized}_privkey"

    @classmethod
    def _decode_key_material(cls, material: Any) -> bytes:
        """Decode only the explicit, length-checked vault encoding."""
        if not isinstance(material, str) or not material.startswith("b64:"):
            raise SigningUnavailable("Vault key material is not in the required encoding")

        encoded = material[4:]
        try:
            key = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SigningUnavailable("Vault key material is invalid") from exc

        if len(key) < cls.minimum_key_bytes:
            raise SigningUnavailable("Vault key material is too short")
        return key

    def sign(self, chain: str, agent_id: str, unsigned_tx: Dict[str, Any]) -> Dict[str, Any]:
        """Return a signed transaction without exposing the private key."""
        if not agent_id or len(agent_id) > 128:
            raise SigningUnavailable("Invalid agent identifier")

        provider = get_provider(chain)
        try:
            profile = self._vault.get_agent_keys(agent_id)
            material = profile[self._key_name(chain)]
        except (KeyError, PermissionError, TypeError) as exc:
            raise SigningUnavailable("Vault key profile is unavailable") from exc

        private_key = self._decode_key_material(material)
        signature = provider.sign_tx(unsigned_tx, private_key)
        return {"unsigned_tx": unsigned_tx, "signature": signature}

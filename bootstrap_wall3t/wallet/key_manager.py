"""Key management utilities for the Sats‑Stack wallet.

* Generates a BIP‑39 24‑word mnemonic (placeholder implementation).
* Derives a simple private key for each supported chain (Bitcoin, Ethereum).
* In a real deployment the keys would be stored encrypted in the PQC vault.
"""
import os
import secrets
import hashlib
import hmac
from typing import Dict

# ---------------------------------------------------------------------------
# Mnemonic handling (placeholder – uses os.urandom and hex for demo purposes)
# ---------------------------------------------------------------------------

def generate_mnemonic() -> str:
    """Return a pseudo‑mnemonic (24 words) for demo purposes.
    In production replace with a proper BIP‑39 library (e.g. `mnemonic`).
    """
    # 256‑bit entropy → 24 words (placeholder: hex groups)
    entropy = secrets.token_bytes(32)
    # Very naive word list – just hex pairs for now
    words = [f"word{int.from_bytes(entropy[i:i+1], 'big')}" for i in range(32)]
    # Take first 24 words
    return " ".join(words[:24])

# ---------------------------------------------------------------------------
# Simple deterministic key derivation (HMAC‑SHA256 of mnemonic + chain)
# ---------------------------------------------------------------------------

def _derive_key(mnemonic: str, chain: str) -> bytes:
    """Derive a 32‑byte private key from the mnemonic and a chain name.
    This is *not* BIP‑32 – just a deterministic placeholder.
    """
    seed = hashlib.sha256(mnemonic.encode()).digest()
    return hmac.new(seed, chain.encode(), hashlib.sha256).digest()

def get_private_key(mnemonic: str, chain: str) -> str:
    """Return the private key as a hex string for the requested chain.

    Args:
        mnemonic: The 24‑word mnemonic string.
        chain:    "bitcoin" or "ethereum" (case‑insensitive).
    """
    key_bytes = _derive_key(mnemonic, chain.lower())
    return key_bytes.hex()

# ---------------------------------------------------------------------------
# Public‑key/address helpers (very simplified placeholders)
# ---------------------------------------------------------------------------

def get_bitcoin_address(private_key_hex: str) -> str:
    """Return a mock Bitcoin address derived from the private key.
    Real implementation would use secp256k1 and Base58Check.
    """
    # Use a hash of the key as a fake address
    return "bc1" + hashlib.sha256(bytes.fromhex(private_key_hex)).hexdigest()[:30]

def get_ethereum_address(private_key_hex: str) -> str:
    """Return a mock Ethereum address (0x…) derived from the private key.
    Real implementation would use eth_keys / eth_account.
    """
    addr = hashlib.sha256(bytes.fromhex(private_key_hex)).hexdigest()[-40:]
    return "0x" + addr

# ---------------------------------------------------------------------------
# Exported helper dict for convenience
# ---------------------------------------------------------------------------
DEFAULT_CHAIN_KEYS: Dict[str, str] = {
    "bitcoin": "bitcoin",
    "ethereum": "ethereum",
}

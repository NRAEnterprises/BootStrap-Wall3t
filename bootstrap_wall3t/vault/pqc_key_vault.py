"""
Quantum-Resistant Sovereign Key Vault (NIST FIPS 203 ML-KEM & NIST FIPS 204 ML-DSA).
Implements:
1. ML-KEM-768 hybrid envelope encryption for the Key Ledger.
2. ML-DSA-65 post-quantum digital signatures for agent access control and authorizations.
3. Rotating session public key ceremony for one-time manual unlocking.
4. Ephemeral RAM-only key residency with automatic zeroization on termination.
"""

import base64
import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from bootstrap_wall3t.core.security import SecureBuffer, lock_process_memory, zero_memory


class PQCKeyVault:
    """
    Isolated Post-Quantum Key Vault.
    Completely decoupled from Automations Vault (HashiCorp).
    """

    def __init__(self, ledger_path: Optional[str] = None):
        self.ledger_path = Path(ledger_path or "./data/vault/pqc_ledger.enc")
        # In-memory ephemeral ledger: agent_id -> dict of secrets
        self._memory_enclave: Dict[str, SecureBuffer] = {}
        self._session_active = False
        self._current_session_pubkey_bytes: Optional[bytes] = None
        
        # Lock RAM to prevent swapping
        lock_process_memory()

    # ==========================================
    # Session Ceremony & Rotating Public Key
    # ==========================================
    @staticmethod
    def generate_session_keypair() -> Tuple[mlkem.MLKEM768PrivateKey, bytes]:
        """
        Generates an ephemeral rotating ML-KEM-768 keypair for the operator ceremony.
        Returns: (private_key_obj, serialized_public_key_bytes)
        """
        priv = mlkem.MLKEM768PrivateKey.generate()
        # MLKEM768 has raw public bytes available or encapsulation directly
        return priv, priv.public_key()

    @staticmethod
    def generate_agent_identity() -> Tuple[mldsa.MLDSA65PrivateKey, bytes]:
        """
        Generates an agent's post-quantum signature keypair (ML-DSA-65).
        Used by the agent to prove its identity when requesting wallet operations.
        """
        priv = mldsa.MLDSA65PrivateKey.generate()
        return priv, priv.public_key()

    # ==========================================
    # Ledger Encryption (NIST FIPS 203 ML-KEM + AES-256-GCM)
    # ==========================================
    def encrypt_ledger(self, ledger_data: Dict[str, Any], recipient_pubkey: mlkem.MLKEM768PublicKey) -> bytes:
        """
        Encrypts the master agent key ledger using ML-KEM-768 encapsulation + AES-256-GCM.
        """
        # 1. ML-KEM Encapsulation -> (shared_secret, ciphertext)
        shared_secret, kem_ciphertext = recipient_pubkey.encapsulate()

        # 2. Derive 256-bit AES key via HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"bootstrap_wall3t-pqc-vault-v1",
            info=b"ledger-envelope-encryption",
        )
        aes_key = hkdf.derive(shared_secret)

        # 3. Encrypt JSON payload with AES-GCM
        payload_bytes = json.dumps(ledger_data).encode("utf-8")
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        encrypted_payload = aesgcm.encrypt(nonce, payload_bytes, None)

        # 4. Pack envelope: [kem_len (4 bytes)][kem_ciphertext][nonce (12 bytes)][encrypted_payload]
        envelope = {
            "kem_ciphertext": base64.b64encode(kem_ciphertext).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "data": base64.b64encode(encrypted_payload).decode("utf-8"),
            "algo_kem": "ML-KEM-768",
            "algo_cipher": "AES-256-GCM",
        }
        return json.dumps(envelope, indent=2).encode("utf-8")

    def save_encrypted_ledger(self, ledger_data: Dict[str, Any], recipient_pubkey: mlkem.MLKEM768PublicKey):
        """Persists the PQC-encrypted ledger to disk."""
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        raw_envelope = self.encrypt_ledger(ledger_data, recipient_pubkey)
        self.ledger_path.write_bytes(raw_envelope)

    # ==========================================
    # Manual Opening Ceremony (Decrypt into RAM only)
    # ==========================================
    def unlock_session(self, operator_privkey: mlkem.MLKEM768PrivateKey, raw_envelope_bytes: Optional[bytes] = None) -> bool:
        """
        Manual opening ceremony executed once at the start of the automations flow.
        Decrypts the ledger strictly into volatile memory (RAM), wrapped in SecureBuffers.
        Zero plaintext is written to disk.
        """
        if raw_envelope_bytes is None:
            if not self.ledger_path.exists():
                raise FileNotFoundError(f"PQC Ledger file not found at {self.ledger_path}")
            raw_envelope_bytes = self.ledger_path.read_bytes()

        envelope = json.loads(raw_envelope_bytes.decode("utf-8"))
        kem_ciphertext = base64.b64decode(envelope["kem_ciphertext"])
        nonce = base64.b64decode(envelope["nonce"])
        encrypted_payload = base64.b64decode(envelope["data"])

        # 1. ML-KEM Decapsulation
        shared_secret = operator_privkey.decapsulate(kem_ciphertext)

        # 2. Derive AES Key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"bootstrap_wall3t-pqc-vault-v1",
            info=b"ledger-envelope-encryption",
        )
        aes_key = hkdf.derive(shared_secret)

        # 3. Decrypt AES-GCM
        aesgcm = AESGCM(aes_key)
        decrypted_bytes = aesgcm.decrypt(nonce, encrypted_payload, None)

        # 4. Ingest into in-memory secure enclave
        ledger = json.loads(decrypted_bytes.decode("utf-8"))
        
        # Clear existing
        self.wipe_session()

        for agent_id, secrets in ledger.items():
            self._memory_enclave[agent_id] = SecureBuffer(json.dumps(secrets).encode("utf-8"))

        self._session_active = True
        return True

    # ==========================================
    # Agent In-Memory Retrieval & Authorization
    # ==========================================
    def get_agent_keys(self, agent_id: str, auth_signature: Optional[bytes] = None, agent_pubkey: Optional[mldsa.MLDSA65PublicKey] = None) -> Dict[str, Any]:
        """
        Retrieves agent keys from RAM.
        If an agent_pubkey and auth_signature are provided, verifies ML-DSA signature before releasing keys.
        """
        if not self._session_active:
            raise PermissionError("PQC Vault session is locked. Complete manual opening ceremony first.")

        if agent_id not in self._memory_enclave:
            raise KeyError(f"No key profile found in memory for agent: {agent_id}")

        # Optional ML-DSA verification for zero-trust multi-agent enclaves
        if agent_pubkey is not None and auth_signature is not None:
            challenge = f"auth:{agent_id}".encode("utf-8")
            try:
                agent_pubkey.verify(auth_signature, challenge)
            except Exception as e:
                raise PermissionError(f"ML-DSA authentication failed for agent {agent_id}: {str(e)}")

        raw_json = self._memory_enclave[agent_id].read()
        return json.loads(raw_json.decode("utf-8"))

    # ==========================================
    # Automated Ephemeral Wipe
    # ==========================================
    def wipe_session(self):
        """
        Immediately wipes and zeroizes all decrypted keys and memory buffers.
        Called automatically on shutdown or workflow termination.
        """
        for agent_id, buf in self._memory_enclave.items():
            buf.wipe()
        self._memory_enclave.clear()
        self._session_active = False

    def is_unlocked(self) -> bool:
        return self._session_active

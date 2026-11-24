"""Typed transport DTOs for the Rust wallet-core EVM gate.

Tickets are untrusted transport values. Positive validation requires both a
BWAU envelope signed by an allowlisted wallet-core key and a ticket-context
signature covering every ticket field that is not part of the generic BWAU
context. No public key is accepted from the ticket itself.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
import time
from typing import Any, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_AUTH_MAGIC = b"BWAU"
_AUTH_VERSION = 1
_AUTH_DOMAIN = b"BOOTSTRAP-WALL3T/AUTHENTICATED-WIRE/V1\x00"
_TICKET_DOMAIN = b"BOOTSTRAP-WALL3T/AUTHENTICATED-TICKET/V1\x00"
_EVM_KIND = 7
_NONCE_LEN = 16
_MAX_PAYLOAD = 8 * 1024 * 1024
_MAX_SIGNATURE = 16 * 1024
_MAX_TEXT = 512


def _u16(value: int) -> bytes:
    return struct.pack(">H", value)


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def _bytes(value: bytes) -> bytes:
    return _u32(len(value)) + value


def _text(value: str) -> bytes:
    return _bytes(value.encode("utf-8"))


def _valid_text(value: str, name: str, maximum: int = _MAX_TEXT) -> None:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise ValueError(f"authenticated {name} is invalid")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"authenticated {name} contains control characters")


@dataclass(frozen=True)
class EvmTransactionIntentRequest:
    request_id: str
    caller_principal: str
    intent: Mapping[str, Any]
    init_code: bytes | None


@dataclass(frozen=True)
class RegisteredVerificationKey:
    """Public-only key record provisioned outside the untrusted ticket."""
    key_id: str
    signer: str
    public_key: bytes
    not_before_unix: int = 0
    expires_at_unix: int | None = None
    revoked: bool = False


class TrustedKeyRegistry:
    """Fail-closed Ed25519 allowlist; private key material is not accepted."""
    def __init__(self, keys: Mapping[str, RegisteredVerificationKey] | None = None) -> None:
        self._keys = dict(keys or {})
        for key in self._keys.values():
            self._validate_record(key)

    @staticmethod
    def _validate_record(key: RegisteredVerificationKey) -> None:
        _valid_text(key.key_id, "key identifier")
        _valid_text(key.signer, "signer")
        if type(key.public_key) is not bytes or len(key.public_key) != 32:
            raise ValueError("verification key must contain exactly 32 public bytes")
        if type(key.not_before_unix) is not int or key.not_before_unix < 0:
            raise ValueError("verification key not-before is invalid")
        if key.expires_at_unix is not None and (
            type(key.expires_at_unix) is not int or key.expires_at_unix <= key.not_before_unix
        ):
            raise ValueError("verification key validity window is invalid")
        if type(key.revoked) is not bool:
            raise ValueError("verification key revocation flag is invalid")

    def verify(self, *, signer: str, key_id: str, message: bytes, signature: bytes, now_unix: int) -> None:
        key = self._keys.get(key_id)
        if key is None:
            raise ValueError("unknown wallet-core verification key")
        if key.signer != signer:
            raise ValueError("verification key signer mismatch")
        if key.revoked:
            raise ValueError("wallet-core verification key is revoked")
        if now_unix < key.not_before_unix:
            raise ValueError("wallet-core verification key is not active")
        if key.expires_at_unix is not None and now_unix >= key.expires_at_unix:
            raise ValueError("wallet-core verification key is expired")
        if type(signature) is not bytes or len(signature) != 64:
            raise ValueError("signature must be an Ed25519 signature")
        try:
            Ed25519PublicKey.from_public_bytes(key.public_key).verify(signature, message)
        except (ValueError, InvalidSignature) as exc:
            raise ValueError("wallet-core signature rejected") from exc


@dataclass(frozen=True)
class SimulationTicket:
    request_id: str
    intent_id: str
    wire_version: int
    record_kind: int
    canonical_payload: bytes
    intent_digest: bytes
    registry_version: int
    simulation_hash: bytes
    policy_id: str
    capability_id: str
    wallet_id: str
    signer_key_id: str
    subject: str
    expires_at_unix: int
    nonce: bytes
    authenticated_envelope: bytes
    ticket_signature: bytes


@dataclass(frozen=True)
class ValidatedSimulationTicket:
    """A ticket that passed structural and cryptographic validation."""
    ticket: SimulationTicket


@dataclass(frozen=True)
class SigningAuthorization:
    ticket: SimulationTicket
    authenticated_envelope: bytes
    signer_key_id: str
    registry_version: int
    intent_digest: bytes
    signer_binding: bytes
    raw_signed_transaction: bytes


@dataclass(frozen=True)
class SignedEvmTransaction:
    ticket: SimulationTicket
    authorization: SigningAuthorization
    raw_signed_transaction: bytes
    transaction_fields: Mapping[str, Any]


@dataclass(frozen=True)
class BroadcastPermit:
    intent_id: str
    intent_digest: bytes
    registry_version: int
    signer_key_id: str
    permit: bytes


class WalletCoreGate(Protocol):
    def simulate(self, request: EvmTransactionIntentRequest) -> SimulationTicket: ...
    def authorize_signing(self, ticket: SimulationTicket) -> SigningAuthorization: ...
    def authorize_broadcast(self, authorization: SigningAuthorization, signed: SignedEvmTransaction) -> BroadcastPermit: ...
    def authorize_read(self, *, operation: str, chain_id: int, contract: str, language: str) -> None: ...


def _payload_hash(kind: int, payload: bytes) -> bytes:
    return hashlib.sha256(_AUTH_DOMAIN + _u16(_AUTH_VERSION) + bytes([kind]) + _bytes(payload)).digest()


def _signed_message(*, kind: int, signer: str, key_id: str, subject: str, registry_version: int,
                    expires_at_unix: int, nonce: bytes, payload_hash: bytes) -> bytes:
    return (_AUTH_DOMAIN + _u16(_AUTH_VERSION) + bytes([kind]) + _text(signer) + _text(key_id)
            + _text(subject) + _u64(registry_version) + _u64(expires_at_unix) + nonce + payload_hash)


def _read_u32(data: bytes, cursor: int) -> tuple[int, int]:
    if cursor + 4 > len(data):
        raise ValueError("authenticated envelope is truncated")
    return int.from_bytes(data[cursor:cursor + 4], "big"), cursor + 4


def _read_bytes(data: bytes, cursor: int, maximum: int) -> tuple[bytes, int]:
    length, cursor = _read_u32(data, cursor)
    if length > maximum or cursor + length > len(data):
        raise ValueError("authenticated envelope length is invalid")
    return data[cursor:cursor + length], cursor + length


def _read_text(data: bytes, cursor: int, maximum: int) -> tuple[str, int]:
    raw, cursor = _read_bytes(data, cursor, maximum)
    try:
        return raw.decode("utf-8"), cursor
    except UnicodeDecodeError as exc:
        raise ValueError("authenticated envelope contains invalid UTF-8") from exc


def _parse_envelope(envelope: bytes) -> tuple[int, str, str, str, int, int, bytes, bytes, bytes, bytes]:
    if type(envelope) is not bytes or len(envelope) > _MAX_PAYLOAD + _MAX_SIGNATURE + 2048:
        raise ValueError("authenticated envelope is invalid")
    if envelope[:4] != _AUTH_MAGIC:
        raise ValueError("authenticated envelope magic mismatch")
    cursor = 4
    if cursor + 3 > len(envelope):
        raise ValueError("authenticated envelope is truncated")
    version = int.from_bytes(envelope[cursor:cursor + 2], "big")
    cursor += 2
    kind = envelope[cursor]
    cursor += 1
    if version != _AUTH_VERSION or not 1 <= kind <= 7:
        raise ValueError("unsupported authenticated envelope identity")
    signer, cursor = _read_text(envelope, cursor, 256)
    key_id, cursor = _read_text(envelope, cursor, 256)
    subject, cursor = _read_text(envelope, cursor, 512)
    if cursor + 8 + 8 + _NONCE_LEN > len(envelope):
        raise ValueError("authenticated envelope is truncated")
    registry_version = int.from_bytes(envelope[cursor:cursor + 8], "big")
    cursor += 8
    expires_at = int.from_bytes(envelope[cursor:cursor + 8], "big")
    cursor += 8
    nonce = envelope[cursor:cursor + _NONCE_LEN]
    cursor += _NONCE_LEN
    payload, cursor = _read_bytes(envelope, cursor, _MAX_PAYLOAD)
    if cursor + 32 > len(envelope):
        raise ValueError("authenticated envelope is truncated")
    payload_hash = envelope[cursor:cursor + 32]
    cursor += 32
    signature, cursor = _read_bytes(envelope, cursor, _MAX_SIGNATURE)
    if cursor != len(envelope) or not signature:
        raise ValueError("authenticated envelope has trailing or missing data")
    if _payload_hash(kind, payload) != payload_hash:
        raise ValueError("authenticated envelope payload hash mismatch")
    return kind, signer, key_id, subject, registry_version, expires_at, nonce, payload, payload_hash, signature


def _ticket_context_message(ticket: SimulationTicket, *, chain_id: int) -> bytes:
    parts = [_TICKET_DOMAIN, _u16(1), _u64(chain_id), _text(ticket.request_id), _text(ticket.intent_id),
             _u16(ticket.wire_version), bytes([ticket.record_kind]), _bytes(ticket.canonical_payload),
             ticket.intent_digest, _u64(ticket.registry_version), ticket.simulation_hash,
             _text(ticket.policy_id), _text(ticket.capability_id), _text(ticket.wallet_id),
             _text(ticket.signer_key_id), _text(ticket.subject), _u64(ticket.expires_at_unix), ticket.nonce]
    return b"".join(parts)


def validate_ticket(ticket: SimulationTicket, *, chain_id: int, key_registry: TrustedKeyRegistry,
                    now_unix: int | None = None) -> ValidatedSimulationTicket:
    """Return an immutable ticket only after both required signatures verify."""
    if type(ticket) is not SimulationTicket:
        raise TypeError("ticket must be an exact immutable SimulationTicket")
    if not isinstance(key_registry, TrustedKeyRegistry):
        raise TypeError("a trusted wallet-core key registry is required")
    if type(chain_id) is not int or chain_id <= 0:
        raise TypeError("chain id must be a positive int")
    now = int(time.time()) if now_unix is None else now_unix
    if type(now) is not int or now < 0:
        raise TypeError("now_unix must be a non-negative int")
    if any(type(value) is not int for value in (ticket.wire_version, ticket.record_kind, ticket.registry_version, ticket.expires_at_unix)):
        raise TypeError("ticket numeric fields must be exact ints")
    binary_fields = (ticket.canonical_payload, ticket.intent_digest, ticket.simulation_hash, ticket.nonce,
                     ticket.authenticated_envelope, ticket.ticket_signature)
    if any(type(value) is not bytes for value in binary_fields):
        raise TypeError("ticket binary fields must be exact bytes")
    if ticket.wire_version != 1 or ticket.record_kind != _EVM_KIND:
        raise ValueError("unsupported wallet-core ticket wire identity")
    if len(ticket.canonical_payload) < 7 or ticket.canonical_payload[:4] != b"BW3C" or ticket.canonical_payload[4:6] != b"\x00\x01" or ticket.canonical_payload[6] != _EVM_KIND:
        raise ValueError("ticket payload header mismatch")
    if len(ticket.intent_digest) != 32 or len(ticket.simulation_hash) != 32:
        raise ValueError("ticket digest fields must be 32 bytes")
    if hashlib.sha256(ticket.canonical_payload).digest() != ticket.intent_digest:
        raise ValueError("ticket intent digest does not match canonical payload")
    if len(ticket.nonce) != _NONCE_LEN or ticket.nonce == b"\x00" * _NONCE_LEN:
        raise ValueError("ticket nonce is invalid")
    if ticket.registry_version == 0 or ticket.expires_at_unix <= now:
        raise ValueError("ticket validity context is invalid or expired")
    for value, name in ((ticket.request_id, "request id"), (ticket.intent_id, "intent id"), (ticket.policy_id, "policy id"),
                        (ticket.capability_id, "capability id"), (ticket.wallet_id, "wallet id"),
                        (ticket.signer_key_id, "signer key id"), (ticket.subject, "subject")):
        _valid_text(value, name)

    kind, signer, key_id, subject, registry_version, expiry, nonce, payload, payload_hash, signature = _parse_envelope(ticket.authenticated_envelope)
    if (kind, payload, key_id, subject, registry_version, expiry, nonce) != (ticket.record_kind, ticket.canonical_payload, ticket.signer_key_id, ticket.subject, ticket.registry_version, ticket.expires_at_unix, ticket.nonce):
        raise ValueError("authenticated envelope is not bound to the exact ticket")
    key_registry.verify(signer=signer, key_id=key_id,
                        message=_signed_message(kind=kind, signer=signer, key_id=key_id, subject=subject,
                                                registry_version=registry_version, expires_at_unix=expiry,
                                                nonce=nonce, payload_hash=payload_hash),
                        signature=signature, now_unix=now)
    key_registry.verify(signer=signer, key_id=key_id, message=_ticket_context_message(ticket, chain_id=chain_id),
                        signature=ticket.ticket_signature, now_unix=now)
    return ValidatedSimulationTicket(ticket=ticket)

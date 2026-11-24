"""Durable replay protection for authenticated wallet-core tickets.

Only public replay metadata is persisted: signer, key id, nonce, and expiry.
The registry uses the Rust wallet-core BWNR v1 framing so both boundaries
fail closed on malformed state and consume a nonce only after ticket
verification succeeds.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import struct
import threading
from typing import Iterable

from .wallet_core_gate import (
    SimulationTicket,
    TrustedKeyRegistry,
    ValidatedSimulationTicket,
    validate_ticket,
)

_MAGIC = b"BWNR"
_VERSION = 1
_NONCE_LEN = 16
_MAX_ENTRIES = 100_000
_MAX_TEXT_BYTES = 256


class ReplayError(ValueError):
    """Base class for fail-closed replay-registry errors."""


class ReplayCorrupt(ReplayError):
    pass


class ReplayExpired(ReplayError):
    pass


class ReplayZeroNonce(ReplayError):
    pass


class ReplayAlreadyConsumed(ReplayError):
    pass


class ReplayCapacityExceeded(ReplayError):
    pass


@dataclass(frozen=True, order=True)
class _ReplayKey:
    signer: str
    key_id: str
    nonce: bytes


@dataclass(frozen=True)
class _ReplayRecord:
    expires_at_unix: int


def _text(value: str) -> bytes:
    raw = value.encode("utf-8")
    if not raw or len(raw) > _MAX_TEXT_BYTES:
        raise ReplayCorrupt("replay text field is invalid")
    return struct.pack(">I", len(raw)) + raw


def _encode(entries: dict[_ReplayKey, _ReplayRecord]) -> bytes:
    if len(entries) > _MAX_ENTRIES:
        raise ReplayCapacityExceeded("replay registry capacity exceeded")
    output = bytearray(_MAGIC + struct.pack(">HI", _VERSION, len(entries)))
    for key in sorted(entries):
        if len(key.nonce) != _NONCE_LEN or key.nonce == b"\0" * _NONCE_LEN:
            raise ReplayCorrupt("replay nonce is invalid")
        output.extend(_text(key.signer))
        output.extend(_text(key.key_id))
        output.extend(key.nonce)
        expiry = entries[key].expires_at_unix
        if type(expiry) is not int or expiry < 0:
            raise ReplayCorrupt("replay expiry is invalid")
        output.extend(struct.pack(">Q", expiry))
    return bytes(output)


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.cursor = 0

    def take(self, size: int) -> bytes:
        end = self.cursor + size
        if size < 0 or end > len(self.data):
            raise ReplayCorrupt("replay state is truncated")
        result = self.data[self.cursor:end]
        self.cursor = end
        return result

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def text(self) -> str:
        length = self.u32()
        if length == 0 or length > _MAX_TEXT_BYTES:
            raise ReplayCorrupt("replay text field is invalid")
        try:
            return self.take(length).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReplayCorrupt("replay text field is not UTF-8") from exc


def _decode(data: bytes) -> dict[_ReplayKey, _ReplayRecord]:
    reader = _Reader(data)
    if reader.take(4) != _MAGIC or reader.u16() != _VERSION:
        raise ReplayCorrupt("replay state header is invalid")
    count = reader.u32()
    if count > _MAX_ENTRIES:
        raise ReplayCorrupt("replay state capacity is invalid")
    entries: dict[_ReplayKey, _ReplayRecord] = {}
    for _ in range(count):
        key = _ReplayKey(reader.text(), reader.text(), reader.take(_NONCE_LEN))
        expiry = reader.u64()
        if key.nonce == b"\0" * _NONCE_LEN or key in entries:
            raise ReplayCorrupt("replay state contains an invalid duplicate")
        entries[key] = _ReplayRecord(expiry)
    if reader.cursor != len(data):
        raise ReplayCorrupt("replay state has trailing bytes")
    return entries


class PersistentNonceRegistry:
    """Atomic, public-metadata-only BWNR replay registry."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        if self.path.exists():
            self._entries = _decode(self.path.read_bytes())
        else:
            self._entries: dict[_ReplayKey, _ReplayRecord] = {}
            self._persist(self._entries)

    def _persist(self, entries: dict[_ReplayKey, _ReplayRecord]) -> None:
        temporary = self.path.with_name(self.path.name + ".tmp")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with temporary.open("wb") as handle:
            handle.write(_encode(entries))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)

    def consume(self, *, signer: str, key_id: str, nonce: bytes,
                expires_at_unix: int, now_unix: int) -> None:
        if type(signer) is not str or not signer or type(key_id) is not str or not key_id:
            raise ReplayCorrupt("replay signer or key id is invalid")
        if type(nonce) is not bytes or len(nonce) != _NONCE_LEN or nonce == b"\0" * _NONCE_LEN:
            raise ReplayZeroNonce("replay nonce is invalid")
        if type(expires_at_unix) is not int or type(now_unix) is not int or expires_at_unix <= now_unix:
            raise ReplayExpired("replay ticket is expired")
        with self._lock:
            current = {key: record for key, record in self._entries.items()
                       if record.expires_at_unix > now_unix}
            key = _ReplayKey(signer, key_id, nonce)
            if key in current:
                raise ReplayAlreadyConsumed("replay nonce was already consumed")
            if len(current) >= _MAX_ENTRIES:
                raise ReplayCapacityExceeded("replay registry capacity exceeded")
            current[key] = _ReplayRecord(expires_at_unix)
            self._persist(current)
            self._entries = current

    def verify_and_consume(self, ticket: SimulationTicket, *, chain_id: int,
                           key_registry: TrustedKeyRegistry,
                           now_unix: int) -> ValidatedSimulationTicket:
        validated = validate_ticket(ticket, chain_id=chain_id, key_registry=key_registry, now_unix=now_unix)
        signer, *_ = _ticket_envelope_identity(ticket.authenticated_envelope)
        self.consume(signer=signer, key_id=ticket.signer_key_id, nonce=ticket.nonce,
                     expires_at_unix=ticket.expires_at_unix, now_unix=now_unix)
        return validated


def _ticket_envelope_identity(envelope: bytes) -> tuple[str, str]:
    # Envelope parsing is deliberately delegated to the authenticated boundary.
    from .wallet_core_gate import _parse_envelope
    parsed = _parse_envelope(envelope)
    return parsed[1], parsed[2]

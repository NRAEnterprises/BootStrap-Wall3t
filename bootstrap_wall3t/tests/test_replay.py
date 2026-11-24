import hashlib
import json
from pathlib import Path

import pytest

from bootstrap_wall3t.chain.replay import (
    PersistentNonceRegistry,
    ReplayAlreadyConsumed,
    ReplayCorrupt,
)
from bootstrap_wall3t.chain.wallet_core_gate import (
    RegisteredVerificationKey,
    SimulationTicket,
    TrustedKeyRegistry,
)

FIXTURE = Path(__file__).parents[2] / "fixtures/bwau/evm_simulation_ticket_v1.json"


def _ticket_and_keys():
    fixture = json.loads(FIXTURE.read_text())
    raw = fixture["ticket"]
    ticket = SimulationTicket(
        request_id=raw["request_id"],
        intent_id=raw["intent_id"],
        wire_version=raw["wire_version"],
        record_kind=raw["record_kind"],
        canonical_payload=bytes.fromhex(raw["canonical_payload_hex"]),
        intent_digest=bytes.fromhex(raw["intent_digest_sha256"]),
        registry_version=raw["registry_version"],
        simulation_hash=bytes.fromhex(raw["simulation_hash_hex"]),
        policy_id=raw["policy_id"],
        capability_id=raw["capability_id"],
        wallet_id=raw["wallet_id"],
        signer_key_id=raw["signer_key_id"],
        subject=raw["subject"],
        expires_at_unix=raw["expires_at_unix"],
        nonce=bytes.fromhex(raw["nonce_hex"]),
        authenticated_envelope=bytes.fromhex(fixture["envelope_hex"]),
        ticket_signature=bytes.fromhex(fixture["ticket_signature_hex"]),
    )
    registry = TrustedKeyRegistry({
        raw["signer_key_id"]: RegisteredVerificationKey(
            raw["signer_key_id"], fixture["signer"], bytes.fromhex(fixture["public_key_hex"])
        )
    })
    return fixture, ticket, registry


def test_verify_and_consume_persists_and_rejects_replay(tmp_path):
    _, ticket, registry = _ticket_and_keys()
    path = tmp_path / "replay.bin"
    replay = PersistentNonceRegistry(path)

    validated = replay.verify_and_consume(ticket, chain_id=1, key_registry=registry, now_unix=1_700_000_000)
    assert validated.ticket == ticket
    with pytest.raises(ReplayAlreadyConsumed):
        replay.verify_and_consume(ticket, chain_id=1, key_registry=registry, now_unix=1_700_000_000)

    reopened = PersistentNonceRegistry(path)
    with pytest.raises(ReplayAlreadyConsumed):
        reopened.verify_and_consume(ticket, chain_id=1, key_registry=registry, now_unix=1_700_000_000)


def test_invalid_signature_does_not_consume_nonce(tmp_path):
    _, ticket, registry = _ticket_and_keys()
    invalid = SimulationTicket(**{**ticket.__dict__, "ticket_signature": hashlib.sha256(b"invalid").digest() * 2})
    replay = PersistentNonceRegistry(tmp_path / "replay.bin")
    with pytest.raises(ValueError, match="signature rejected"):
        replay.verify_and_consume(invalid, chain_id=1, key_registry=registry, now_unix=1_700_000_000)
    assert replay.path.read_bytes() == b"BWNR\x00\x01\x00\x00\x00\x00"


def test_corrupt_state_fails_closed(tmp_path):
    path = tmp_path / "replay.bin"
    path.write_bytes(b"BWNR\x00\x01\x00\x00\x00\x00\x01")
    with pytest.raises(ReplayCorrupt):
        PersistentNonceRegistry(path)

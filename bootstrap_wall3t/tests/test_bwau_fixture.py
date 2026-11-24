import hashlib
import json
from pathlib import Path

from bootstrap_wall3t.chain.wallet_core_gate import (
    RegisteredVerificationKey,
    SimulationTicket,
    TrustedKeyRegistry,
    _parse_envelope,
    _signed_message,
    _ticket_context_message,
    validate_ticket,
)

FIXTURE = Path(__file__).parents[2] / "fixtures/bwau/evm_simulation_ticket_v1.json"


def test_python_reproduces_bwau_messages_and_ticket_signature_fixture():
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
    key_registry = TrustedKeyRegistry({
        raw["signer_key_id"]: RegisteredVerificationKey(
            raw["signer_key_id"], fixture["signer"], bytes.fromhex(fixture["public_key_hex"])
        )
    })

    parsed = _parse_envelope(ticket.authenticated_envelope)
    assert parsed[8].hex() == fixture["payload_hash_sha256"]
    assert _signed_message(
        kind=parsed[0], signer=parsed[1], key_id=parsed[2], subject=parsed[3],
        registry_version=parsed[4], expires_at_unix=parsed[5], nonce=parsed[6], payload_hash=parsed[8]
    ).hex() == fixture["signed_message_hex"]
    assert _ticket_context_message(ticket, chain_id=1).hex() == fixture["ticket_context_message_hex"]
    assert validate_ticket(ticket, chain_id=1, key_registry=key_registry, now_unix=1_700_000_000).ticket == ticket
    assert hashlib.sha256(ticket.canonical_payload).hexdigest() == raw["intent_digest_sha256"]

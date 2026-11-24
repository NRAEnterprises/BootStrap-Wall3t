import hashlib
import json
import struct
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bootstrap_wall3t.chain.evm_contracts import (
    AuthorizationError,
    ContractArtifact,
    EVMContractAdapter,
    _selector,
    artifact_from_compiler_output,
    write_deployment_manifest,
)
from bootstrap_wall3t.chain.wallet_core_gate import (
    BroadcastPermit,
    SigningAuthorization,
    SimulationTicket,
    RegisteredVerificationKey,
    TrustedKeyRegistry,
    ValidatedSimulationTicket,
    _payload_hash,
    _signed_message,
    _ticket_context_message,
    validate_ticket,
)


ADDRESS = "0x" + "11" * 20
DEPLOYED = "0x" + "22" * 20
TX_HASH = "0x" + "33" * 32
DOMAIN = "0x" + "44" * 32


class Gate:
    def __init__(self, deny=False):
        self.deny = deny
        self.calls = []
        self.ticket = None
        self.signing_key = Ed25519PrivateKey.generate()
        public_key = self.signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.key_registry = TrustedKeyRegistry({
            "key-1": RegisteredVerificationKey("key-1", "rust-wallet-core", public_key)
        })

    def authorize_read(self, *, operation, chain_id, contract, language):
        self.calls.append((operation, chain_id, contract, language))
        if self.deny:
            raise AuthorizationError("wallet-core denied read")

    def simulate(self, request):
        self.calls.append(("simulate", request.intent["operation"], request.intent["from"]))
        if self.deny:
            raise AuthorizationError("wallet-core denied simulation")
        payload = b"BW3C" + b"\x00\x01\x07" + request.request_id.encode()
        ticket = SimulationTicket(
            request_id=request.request_id,
            intent_id=request.request_id,
            wire_version=1,
            record_kind=7,
            canonical_payload=payload,
            intent_digest=hashlib.sha256(payload).digest(),
            registry_version=1,
            simulation_hash=hashlib.sha256(b"simulation").digest(),
            policy_id="policy-1",
            capability_id="cap-1",
            wallet_id="wallet-1",
            signer_key_id="key-1",
            subject="wallet-1",
            expires_at_unix=2_000_000_000,
            nonce=b"1" * 16,
            authenticated_envelope=b"",
            ticket_signature=b"",
        )
        payload_hash = _payload_hash(ticket.record_kind, ticket.canonical_payload)
        signed_message = _signed_message(
            kind=ticket.record_kind,
            signer="rust-wallet-core",
            key_id=ticket.signer_key_id,
            subject=ticket.subject,
            registry_version=ticket.registry_version,
            expires_at_unix=ticket.expires_at_unix,
            nonce=ticket.nonce,
            payload_hash=payload_hash,
        )
        lp = lambda value: struct.pack(">I", len(value.encode() if isinstance(value, str) else value)) + (value.encode() if isinstance(value, str) else value)
        envelope = (
            b"BWAU" + struct.pack(">H", 1) + bytes([ticket.record_kind])
            + lp(b"rust-wallet-core") + lp(ticket.signer_key_id) + lp(ticket.subject)
            + struct.pack(">Q", ticket.registry_version)
            + struct.pack(">Q", ticket.expires_at_unix) + ticket.nonce
            + lp(ticket.canonical_payload) + payload_hash
            + lp(self.signing_key.sign(signed_message))
        )
        ticket = replace(
            ticket,
            authenticated_envelope=envelope,
            ticket_signature=self.signing_key.sign(
                _ticket_context_message(ticket, chain_id=31337)
            ),
        )
        self.ticket = ticket
        return self.ticket

    def authorize_signing(self, ticket):
        if self.deny:
            raise AuthorizationError("wallet-core denied signing")
        return SigningAuthorization(
            ticket=ticket,
            authenticated_envelope=b"BWAU-envelope",
            signer_key_id=ticket.signer_key_id,
            registry_version=ticket.registry_version,
            intent_digest=ticket.intent_digest,
            signer_binding=b"signer-binding",
            raw_signed_transaction=b"\xde\xad\xbe\xef",
        )

    def authorize_broadcast(self, authorization, signed):
        self.calls.append(("broadcast", authorization.intent_digest, signed.raw_signed_transaction))
        if self.deny:
            raise AuthorizationError("wallet-core denied broadcast")
        return BroadcastPermit(
            intent_id=authorization.ticket.intent_id,
            intent_digest=authorization.intent_digest,
            registry_version=authorization.registry_version,
            signer_key_id=authorization.signer_key_id,
            permit=b"permit",
        )


class RPC:
    def __init__(self):
        self.calls = []

    def __call__(self, method, params):
        self.calls.append((method, params))
        if method == "eth_chainId":
            return "0x7a69"
        if method == "eth_getTransactionCount":
            return "0x0"
        if method == "eth_gasPrice":
            return "0x1"
        if method == "eth_sendRawTransaction":
            return TX_HASH
        if method == "eth_getTransactionReceipt":
            return {"status": "0x1", "contractAddress": DEPLOYED}
        if method == "eth_getCode":
            return "0x6001600055"
        if method == "eth_call":
            data = params[0]["data"]
            if data in {_selector("domain()"), _selector("DOMAIN()")}:
                return DOMAIN
            if data == _selector("PROTOCOL_VERSION()"):
                return "0x" + ("0" * 63) + "1"
            expected = int(data[10:74], 16)
            current = int(data[74:138], 16)
            return "0x" + ("0" * 63) + ("1" if expected == current else "0")
        raise AssertionError(f"unexpected RPC method: {method}")


def artifact(language="solidity"):
    return artifact_from_compiler_output(
        name="BoundaryRegistry",
        language=language,
        abi=[],
        bytecode="0x6001600055",
        source=b"boundary source",
    )


def test_solidity_and_vyper_reads_use_typed_wallet_core_gate():
    rpc = RPC()
    gate = Gate()
    adapter = EVMContractAdapter(rpc=rpc, gate=gate, chain_id=31337)

    assert adapter.read_domain(address=ADDRESS, language="solidity") == DOMAIN
    assert adapter.read_domain(address=ADDRESS, language="vyper") == DOMAIN
    assert adapter.read_protocol_version(address=ADDRESS) == 1
    assert adapter.validate_version(address=ADDRESS, language="solidity", expected=1, current=1)
    assert not adapter.validate_version(address=ADDRESS, language="vyper", expected=1, current=2)
    assert len(gate.calls) == 5


def test_deployment_requires_typed_ticket_and_prebroadcast_permit():
    rpc = RPC()
    gate = Gate()
    adapter = EVMContractAdapter(rpc=rpc, gate=gate, chain_id=31337)
    record = adapter.deploy(artifact(), from_address=ADDRESS)

    assert record.address == DEPLOYED
    assert record.chain_id == 31337
    assert record.transaction_hash == TX_HASH
    assert record.source_sha256 == artifact().source_sha256
    assert ("simulate", "Deploy", ADDRESS) in gate.calls
    assert any(call[0] == "broadcast" for call in gate.calls)
    assert ("eth_sendRawTransaction", ["0xdeadbeef"]) in rpc.calls


def test_denied_typed_gate_does_not_broadcast():
    rpc = RPC()
    gate = Gate(deny=True)
    adapter = EVMContractAdapter(rpc=rpc, gate=gate, chain_id=31337)

    with pytest.raises(AuthorizationError):
        adapter.deploy(artifact(), from_address=ADDRESS)

    assert not any(method == "eth_sendRawTransaction" for method, _ in rpc.calls)


def test_unknown_language_fails_closed_before_rpc_call():
    rpc = RPC()
    adapter = EVMContractAdapter(rpc=rpc, gate=Gate(), chain_id=31337)
    with pytest.raises(ValueError, match="unsupported boundary language"):
        adapter.read_domain(address=ADDRESS, language="unknown")


def test_ticket_payload_digest_mismatch_fails_closed():
    gate = Gate()
    ticket = gate.simulate(
        type("Request", (), {"request_id": "request-1", "intent": {"operation": "Deploy", "from": ADDRESS}, "init_code": b""})()
    )
    tampered = SimulationTicket(
        **{**ticket.__dict__, "canonical_payload": ticket.canonical_payload[:-1] + b"x"}
    )
    with pytest.raises(ValueError, match="digest"):
        validate_ticket(tampered, chain_id=31337, key_registry=gate.key_registry)


def test_valid_ticket_is_wrapped_immutably():
    gate = Gate()
    ticket = gate.simulate(
        type(
            "Request",
            (),
            {
                "request_id": "request-1",
                "intent": {"operation": "Deploy", "from": ADDRESS},
                "init_code": b"",
            },
        )()
    )

    validated = validate_ticket(ticket, chain_id=31337, key_registry=gate.key_registry)

    assert isinstance(validated, ValidatedSimulationTicket)
    assert validated.ticket is ticket
    with pytest.raises((AttributeError, TypeError)):
        validated.ticket = ticket


def test_mutable_duck_typed_ticket_is_rejected_before_wrapping():
    class ForgedTicket:
        pass

    with pytest.raises(TypeError, match="exact immutable SimulationTicket"):
        validate_ticket(ForgedTicket(), chain_id=31337, key_registry=Gate().key_registry)


def test_expired_ticket_is_rejected_before_wrapping():
    gate = Gate()
    ticket = gate.simulate(
        type(
            "Request",
            (),
            {
                "request_id": "request-1",
                "intent": {"operation": "Deploy", "from": ADDRESS},
                "init_code": b"",
            },
        )()
    )

    with pytest.raises(ValueError, match="expired|validity"):
        validate_ticket(replace(ticket, expires_at_unix=1), chain_id=31337, key_registry=gate.key_registry)


def test_ticket_context_signature_binds_simulation_hash_and_request_identity():
    gate = Gate()
    ticket = gate.simulate(
        type("Request", (), {"request_id": "request-1", "intent": {"operation": "Deploy", "from": ADDRESS}, "init_code": b""})()
    )
    for field, value in (("simulation_hash", b"s" * 32), ("request_id", "other-request"), ("policy_id", "other-policy")):
        with pytest.raises(ValueError, match="signature|bound"):
            validate_ticket(replace(ticket, **{field: value}), chain_id=31337, key_registry=gate.key_registry)


def test_unknown_key_and_signature_substitution_fail_closed():
    gate = Gate()
    ticket = gate.simulate(
        type("Request", (), {"request_id": "request-1", "intent": {"operation": "Deploy", "from": ADDRESS}, "init_code": b""})()
    )
    unknown_registry = TrustedKeyRegistry()
    with pytest.raises(ValueError, match="unknown"):
        validate_ticket(ticket, chain_id=31337, key_registry=unknown_registry)
    other = Gate().simulate(
        type("Request", (), {"request_id": "request-2", "intent": {"operation": "Deploy", "from": ADDRESS}, "init_code": b""})()
    )
    with pytest.raises(ValueError, match="signature"):
        validate_ticket(replace(ticket, ticket_signature=other.ticket_signature), chain_id=31337, key_registry=gate.key_registry)


def test_malformed_bwau_signature_and_chain_context_fail_closed():
    gate = Gate()
    ticket = gate.simulate(
        type("Request", (), {"request_id": "request-1", "intent": {"operation": "Deploy", "from": ADDRESS}, "init_code": b""})()
    )
    with pytest.raises(ValueError, match="signature"):
        validate_ticket(replace(ticket, authenticated_envelope=ticket.authenticated_envelope[:-1] + b"x"), chain_id=31337, key_registry=gate.key_registry)
    with pytest.raises(ValueError, match="signature"):
        validate_ticket(ticket, chain_id=1, key_registry=gate.key_registry)


def test_verifier_configuration_contains_public_material_only():
    gate = Gate()
    key = gate.key_registry._keys["key-1"]
    assert not hasattr(key, "private_key")
    assert set(key.__dict__) == {"key_id", "signer", "public_key", "not_before_unix", "expires_at_unix", "revoked"}


def test_manifest_contains_public_deployment_metadata_only(tmp_path: Path):
    path = tmp_path / "deployments.json"
    record = EVMContractAdapter(rpc=RPC(), gate=Gate(), chain_id=31337).deploy(
        artifact("vyper"), from_address=ADDRESS
    )

    write_deployment_manifest(str(path), [record])
    payload = json.loads(path.read_text())
    assert payload["schema"] == "bootstrap-wall3t/evm-deployments/v1"
    assert payload["deployments"][0]["language"] == "vyper"
    assert "private_key" not in path.read_text().lower()
    assert "raw_signed" not in path.read_text().lower()


def test_chain_id_mismatch_fails_closed():
    with pytest.raises(Exception, match="does not match configured"):
        EVMContractAdapter(rpc=RPC(), gate=Gate(), chain_id=1)

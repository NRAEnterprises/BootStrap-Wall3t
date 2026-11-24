"""EVM contract deployment and read/write adapter.

This module is deliberately transport- and signer-agnostic. It does not hold
keys, derive accounts, or broadcast unsigned transactions. Callers must inject:

* an authenticated JSON-RPC transport;
* a signer that accepts an unsigned transaction and returns raw signed bytes;
* a wallet-core authorization gate that has already performed simulation and
  the final quarantine/policy read barrier.

The adapter only handles the narrow BoundaryRegistry ABI used by the Solidity
and Vyper targets. It is not a general-purpose Web3 client.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

from .wallet_core_gate import (
    EvmTransactionIntentRequest,
    SignedEvmTransaction,
    TrustedKeyRegistry,
    WalletCoreGate,
    validate_ticket,
)

try:
    from Crypto.Hash import keccak as _keccak_module
except ImportError:  # pragma: no cover - exercised only in a misconfigured install
    _keccak_module = None


class EVMAdapterError(RuntimeError):
    """Base error for fail-closed adapter failures."""


class RPCError(EVMAdapterError):
    """The JSON-RPC endpoint returned an error or malformed response."""


class AuthorizationError(EVMAdapterError):
    """Wallet-core did not authorize the operation."""


class SignerUnavailable(EVMAdapterError):
    """No explicit raw-transaction signer was provided."""


JSONRPCTransport = Any


SOLIDITY_BOUNDARY_ABI: tuple[dict[str, Any], ...] = (
    {
        "inputs": [],
        "name": "DOMAIN",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "PROTOCOL_VERSION",
        "outputs": [{"internalType": "uint64", "name": "", "type": "uint64"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "uint64", "name": "expected", "type": "uint64"},
            {"internalType": "uint64", "name": "current", "type": "uint64"},
        ],
        "name": "validateVersion",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "pure",
        "type": "function",
    },
)

VYPER_BOUNDARY_ABI: tuple[dict[str, Any], ...] = (
    {
        "inputs": [],
        "name": "domain",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "PROTOCOL_VERSION",
        "outputs": [{"name": "", "type": "uint64"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "expected", "type": "uint64"},
            {"name": "current", "type": "uint64"},
        ],
        "name": "validate_version",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "pure",
        "type": "function",
    },
)


@dataclass(frozen=True)
class ContractArtifact:
    """Minimal deployment artifact; bytecode is hex with a mandatory 0x prefix."""

    name: str
    language: str
    abi: tuple[dict[str, Any], ...]
    bytecode: str
    source_sha256: str

    def __post_init__(self) -> None:
        if not self.name or self.language not in {"solidity", "vyper"}:
            raise ValueError("invalid contract artifact identity")
        if not self.bytecode.startswith("0x") or len(self.bytecode) <= 2:
            raise ValueError("deployment bytecode must be non-empty 0x-prefixed hex")
        try:
            bytes.fromhex(self.bytecode[2:])
        except ValueError as exc:
            raise ValueError("deployment bytecode is not hexadecimal") from exc
        if len(self.source_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.source_sha256):
            raise ValueError("source_sha256 must be a lowercase SHA-256 digest")


@dataclass(frozen=True)
class DeploymentRecord:
    """Auditable deployment output; contains no private key or raw signed tx."""

    contract: str
    language: str
    chain_id: int
    address: str
    transaction_hash: str
    source_sha256: str
    protocol_version: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "language": self.language,
            "chain_id": self.chain_id,
            "address": self.address,
            "transaction_hash": self.transaction_hash,
            "source_sha256": self.source_sha256,
            "protocol_version": self.protocol_version,
        }


def _keccak256(data: bytes) -> bytes:
    if _keccak_module is None:
        raise EVMAdapterError("Ethereum Keccak support is unavailable; install pycryptodome")
    digest = _keccak_module.new(digest_bits=256)
    digest.update(data)
    return digest.digest()


def _selector(signature: str) -> str:
    return "0x" + _keccak256(signature.encode("ascii"))[:4].hex()


def _uint64_word(value: int) -> str:
    if not isinstance(value, int) or not 0 <= value < 2**64:
        raise ValueError("uint64 argument is out of range")
    return f"{value:064x}"


def _address(value: str) -> str:
    if not isinstance(value, str) or len(value) != 42 or not value.startswith("0x"):
        raise ValueError("EVM address must be a 0x-prefixed 20-byte value")
    try:
        int(value[2:], 16)
    except ValueError as exc:
        raise ValueError("EVM address is not hexadecimal") from exc
    return value.lower()


class EVMContractAdapter:
    """Authenticated JSON-RPC adapter for the two boundary contract variants."""

    def __init__(
        self,
        *,
        rpc: JSONRPCTransport,
        gate: WalletCoreGate,
        chain_id: int,
        key_registry: TrustedKeyRegistry | None = None,
    ) -> None:
        if chain_id <= 0:
            raise ValueError("chain_id must be positive")
        key_registry = key_registry or getattr(gate, "key_registry", None)
        if not isinstance(key_registry, TrustedKeyRegistry):
            raise TypeError("key_registry must be a trusted wallet-core key registry")
        self._rpc = rpc
        self._gate = gate
        self._key_registry = key_registry
        self.chain_id = chain_id
        observed = self._rpc("eth_chainId", [])
        try:
            observed_id = int(observed, 16)
        except (TypeError, ValueError) as exc:
            raise RPCError("RPC returned an invalid eth_chainId") from exc
        if observed_id != chain_id:
            raise RPCError(f"RPC chain ID {observed_id} does not match configured {chain_id}")

    def deploy(self, artifact: ContractArtifact, *, from_address: str, protocol_version: int = 1) -> DeploymentRecord:
        sender = _address(from_address)
        nonce = self._rpc("eth_getTransactionCount", [sender, "pending"])
        gas_price = self._rpc("eth_gasPrice", [])
        tx: dict[str, Any] = {
            "from": sender,
            "chainId": hex(self.chain_id),
            "nonce": nonce,
            "gas": "0x186a0",
            "maxFeePerGas": gas_price,
            "maxPriorityFeePerGas": gas_price,
            "value": "0x0",
            "data": artifact.bytecode,
        }
        request = EvmTransactionIntentRequest(
            request_id=f"evm-deploy:{artifact.name}:{self.chain_id}:{nonce}",
            caller_principal="evm-adapter",
            intent={
                "operation": "Deploy",
                "chain_id": self.chain_id,
                "from": sender,
                "to": None,
                "nonce": nonce,
                "value": "0x0",
                "gas_limit": tx["gas"],
                "fee": {"model": "eip1559", "max_fee_per_gas": gas_price, "max_priority_fee_per_gas": gas_price},
                "calldata": artifact.bytecode,
                "artifact": {
                    "name": artifact.name,
                    "language": artifact.language,
                    "source_sha256": artifact.source_sha256,
                },
                "protocol_version": protocol_version,
            },
            init_code=bytes.fromhex(artifact.bytecode[2:]),
        )
        ticket = self._gate.simulate(request)
        validated_ticket = validate_ticket(
            ticket, chain_id=self.chain_id, key_registry=self._key_registry
        )
        authorization = self._gate.authorize_signing(validated_ticket.ticket)
        if (
            authorization.ticket != validated_ticket.ticket
            or authorization.intent_digest != validated_ticket.ticket.intent_digest
        ):
            raise AuthorizationError("signing authorization is not bound to simulation ticket")
        if not authorization.raw_signed_transaction:
            raise SignerUnavailable("wallet-core returned no signed transaction")
        signed = SignedEvmTransaction(
            ticket=validated_ticket.ticket,
            authorization=authorization,
            raw_signed_transaction=authorization.raw_signed_transaction,
            transaction_fields=tx,
        )
        permit = self._gate.authorize_broadcast(authorization, signed)
        if (
            permit.intent_digest != validated_ticket.ticket.intent_digest
            or permit.registry_version != validated_ticket.ticket.registry_version
        ):
            raise AuthorizationError("broadcast permit is not bound to the wallet-core ticket")
        raw_signed = "0x" + authorization.raw_signed_transaction.hex()
        tx_hash = self._rpc("eth_sendRawTransaction", [raw_signed])
        receipt = self._wait_for_receipt(tx_hash)
        if receipt.get("status") != "0x1":
            raise RPCError("deployment transaction failed")
        address = receipt.get("contractAddress")
        if not isinstance(address, str):
            raise RPCError("deployment receipt did not include contractAddress")
        address = _address(address)
        code = self._rpc("eth_getCode", [address, "latest"])
        if not isinstance(code, str) or code in {"0x", "0x0"}:
            raise RPCError("deployed contract has no runtime bytecode")
        return DeploymentRecord(
            contract=artifact.name,
            language=artifact.language,
            chain_id=self.chain_id,
            address=address,
            transaction_hash=tx_hash,
            source_sha256=artifact.source_sha256,
            protocol_version=protocol_version,
        )

    def read_domain(self, *, address: str, language: str) -> str:
        contract = _address(address)
        if language not in {"solidity", "vyper"}:
            raise ValueError("unsupported boundary language")
        self._gate.authorize_read(operation="evm_read_domain", chain_id=self.chain_id, contract=contract, language=language)
        name = "DOMAIN()" if language == "solidity" else "domain()"
        result = self._rpc("eth_call", [{"to": contract, "data": _selector(name)}, "latest"])
        if not isinstance(result, str) or len(result) != 66:
            raise RPCError("domain call returned malformed bytes32")
        return result.lower()

    def read_protocol_version(self, *, address: str) -> int:
        contract = _address(address)
        self._gate.authorize_read(operation="evm_read_protocol_version", chain_id=self.chain_id, contract=contract, language="common")
        result = self._rpc(
            "eth_call", [{"to": contract, "data": _selector("PROTOCOL_VERSION()")}, "latest"]
        )
        if not isinstance(result, str) or len(result) < 66:
            raise RPCError("protocol version call returned malformed uint64")
        value = int(result[-64:], 16)
        if value >= 2**64:
            raise RPCError("protocol version exceeds uint64")
        return value

    def validate_version(self, *, address: str, language: str, expected: int, current: int) -> bool:
        contract = _address(address)
        if language not in {"solidity", "vyper"}:
            raise ValueError("unsupported boundary language")
        self._gate.authorize_read(operation="evm_validate_version", chain_id=self.chain_id, contract=contract, language=language)
        name = "validateVersion(uint64,uint64)" if language == "solidity" else "validate_version(uint64,uint64)"
        data = _selector(name) + _uint64_word(expected) + _uint64_word(current)
        result = self._rpc("eth_call", [{"to": contract, "data": data}, "latest"])
        if not isinstance(result, str) or len(result) < 66:
            raise RPCError("version call returned malformed bool")
        return int(result[-64:], 16) == 1

    def _wait_for_receipt(self, tx_hash: str) -> Mapping[str, Any]:
        if not isinstance(tx_hash, str) or not tx_hash.startswith("0x"):
            raise RPCError("RPC returned an invalid transaction hash")
        receipt = self._rpc("eth_getTransactionReceipt", [tx_hash])
        if not isinstance(receipt, Mapping):
            raise RPCError("transaction receipt unavailable")
        return receipt


def artifact_from_compiler_output(
    *, name: str, language: str, abi: list[dict[str, Any]], bytecode: str, source: bytes
) -> ContractArtifact:
    """Build an artifact while binding deployment metadata to source content."""
    return ContractArtifact(
        name=name,
        language=language,
        abi=tuple(abi),
        bytecode=bytecode,
        source_sha256=hashlib.sha256(source).hexdigest(),
    )


def write_deployment_manifest(path: str, records: list[DeploymentRecord]) -> None:
    """Write only public deployment metadata; refuse accidental secret-shaped fields."""
    payload = {"schema": "bootstrap-wall3t/evm-deployments/v1", "deployments": [r.as_dict() for r in records]}
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    lowered = encoded.lower()
    for marker in ("private_key", "mnemonic", "seed", "raw_signed", "secret"):
        if marker in lowered:
            raise ValueError("deployment manifest contains a forbidden secret field")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(encoded)

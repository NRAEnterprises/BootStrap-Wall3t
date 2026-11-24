# WalletCoreGate Protocol and Canonical BW3C EVM Transaction Intent

**Status:** design proposal; not yet implemented

This document resolves Finding #1 from the EVM adapter review. The current generic callback:

```python
gate.authorize(operation, chain_id, contract)
```

is insufficient because it authorizes an operation category rather than the exact transaction that a signer will approve. The replacement protocol binds wallet-core authorization to the complete typed EVM transaction, the policy footprint, the quarantine registry version, the simulation result, and the signer identity.

The protocol deliberately keeps key material inside Rust wallet-core and the configured vault/HSM boundary. Python, Elixir, browser, and chain adapters receive typed opaque tickets and signed results only.

## 1. Security goals

The protocol MUST guarantee all of the following:

1. A signer can sign only the exact transaction represented by an approved wallet-core ticket.
2. Changing any transaction field changes the canonical intent digest and invalidates the ticket.
3. A quarantine registry version change invalidates every outstanding positive ticket, including reversals.
4. The authorization is bound to the chain, wallet, sender, operation, target, value, calldata, deployment bytecode, gas policy, fee policy, policy, capability, and principal.
5. The adapter cannot substitute a different artifact, sender, recipient, calldata, nonce, or fee after authorization.
6. An agent cannot obtain a user/cold-wallet signing capability by changing an identifier in a request.
7. JSON is transport/debug representation only. It is never the signing transcript.
8. Unsupported wire versions, record kinds, operation kinds, address forms, fee models, and extra bytes fail closed.

## 2. Trust boundaries

```text
Untrusted caller / agent / browser / Elixir
        |
        | typed EVM intent request
        v
Rust wallet-core admission
        |
        | quarantine + policy + capability + budget checks
        v
BW3C canonical intent + BWAU authenticated ticket
        |
        | exact-ticket signer binding
        v
Vault/HSM signer owned by wallet-core
        |
        | signed transaction bound to the same payload
        v
EVM chain adapter / authenticated RPC
        |
        | final wallet-core read barrier, then sendRawTransaction
        v
EVM network
```

The EVM adapter MUST NOT own a private key, derive a mnemonic, or accept an arbitrary raw signer that is not bound to the wallet-core ticket.

## 3. Wire allocation

The existing canonical wire header is retained:

```text
magic       = ASCII "BW3C"              4 bytes
wire_version = u16                       2 bytes, big-endian
record_kind  = u8                        1 byte
```

Existing record kinds remain unchanged:

```text
1 AgentAssignment
2 FundingAuthorization
3 VaultPolicy
4 AutomationPolicy
5 AutomationFlow
6 QuarantineEvent
```

The EVM transaction intent uses:

```text
record_kind = 7  // EvmTransactionIntent
```

`WIRE_VERSION = 1` remains the version for this first allocation. A decoder that does not support kind 7 MUST reject it; it MUST NOT reinterpret it as another record type.

The canonical transaction-intent digest is:

```text
intent_digest = SHA-256(canonical_bw3c_bytes)
```

The digest is represented as exactly 32 raw bytes in typed tickets and as lowercase 64-character hexadecimal only in diagnostic or manifest views. The existing BWAU envelope has a separate `payload_hash`, defined below, which also binds the record kind.

## 4. Typed Rust model

The implementation should add these types to `rust/wallet-core`:

```rust
pub const EVM_TRANSACTION_INTENT_KIND: u8 = 7;

pub struct EvmTransactionIntent {
    pub intent_id: IntentId,
    pub wallet_id: UserWalletId,
    pub principal: PrincipalBinding,
    pub operation: EvmOperation,
    pub chain_id: ChainId,
    pub from: EvmAddress,
    pub to: Option<EvmAddress>,
    pub nonce: u64,
    pub value: U256,
    pub gas_limit: u64,
    pub fee: EvmFeePolicy,
    pub calldata: Vec<u8>,
    pub deployment: Option<EvmDeploymentMetadata>,
    pub policy_id: PolicyId,
    pub capability_id: CapabilityId,
    pub document_hash: DocumentHash,
    pub footprint: Vec<EntityRef>,
    pub not_before_unix: u64,
    pub expires_at_unix: u64,
}

pub enum PrincipalBinding {
    User,
    Agent { agent_id: AgentWalletId },
}

pub enum EvmOperation {
    Deploy,
    ContractCall,
}

pub enum EvmFeePolicy {
    Legacy { gas_price: U256 },
    Eip1559 {
        max_fee_per_gas: U256,
        max_priority_fee_per_gas: U256,
    },
}

pub struct EvmDeploymentMetadata {
    pub language: EvmContractLanguage,
    pub contract_name: String,
    pub init_code_hash: [u8; 32],
    pub expected_runtime_code_hash: Option<[u8; 32]>,
    pub source_sha256: [u8; 32],
}

pub enum EvmContractLanguage {
    Solidity,
    Vyper,
}
```

`U256` MUST be a checked 32-byte unsigned integer type. It MUST reject negative values and values above `2^256 - 1`. `EvmAddress` MUST be exactly 20 bytes after chain-specific normalization. The canonical payload MUST NOT contain user-supplied textual address casing.

`IntentId`, `PolicyId`, `CapabilityId`, `DocumentHash`, wallet IDs, and agent IDs use the existing validated opaque identifier rules. No control characters or empty identifiers are accepted.

## 5. Canonical BW3C field layout

All numeric values are big-endian. All variable-length fields use the existing `u32 byte_length + bytes` encoding. Every discriminant is one byte. There are no field names, JSON delimiters, implicit defaults, or map iteration order in the payload.

```text
BW3C header
  4 bytes  magic: "BW3C"
  u16      wire version: 1
  u8       record kind: 7

Intent identity and authority
  str      intent_id
  str      wallet_id
  u8       principal discriminant
             1 = User
             2 = Agent
             if 2: str agent_id
  u8       operation discriminant
             1 = Deploy
             2 = ContractCall

Chain transaction envelope
  u64      chain_id
  [20]     from
  u8       to_present
  if true: [20] to
  u64      nonce
  [32]     value
  u64      gas_limit
  u8       fee discriminant
             1 = Legacy
             2 = EIP-1559
  if Legacy:
    [32]   gas_price
  if EIP-1559:
    [32]   max_fee_per_gas
    [32]   max_priority_fee_per_gas
  bytes    calldata

Deployment binding
  u8       deployment_present
  if true:
    u8     language discriminant
             1 = Solidity
             2 = Vyper
    str    contract_name
    [32]   init_code_hash
    u8     expected_runtime_code_hash_present
    if true: [32] expected_runtime_code_hash
    [32]   source_sha256

Policy and impact binding
  str      policy_id
  str      capability_id
  str      document_hash
  u32      footprint_count
  repeated footprint_count times:
    EntityRef using the existing explicit entity discriminants

Validity
  u64      not_before_unix
  u64      expires_at_unix
```

### Canonicalization rules

Before encoding:

- `from` and `to` are normalized to raw 20-byte addresses.
- `chain_id` MUST be positive.
- `nonce`, `gas_limit`, and validity timestamps are checked for overflow.
- `expires_at_unix` MUST be greater than `not_before_unix`.
- `value` and fee values are encoded as exactly 32 bytes.
- `calldata` is raw bytes, never a hex string in the canonical model.
- `to` MUST be absent for `Deploy` and present for `ContractCall`.
- `deployment` MUST be present for `Deploy` and absent for ordinary `ContractCall`.
- `init_code_hash` MUST equal `SHA-256(init_code)` computed by the artifact/deployment boundary. If the implementation also records an EVM Keccak code hash, it is an additional field and does not replace the required SHA-256 source binding.
- `source_sha256` MUST match a reviewed artifact registry entry in wallet-core.
- The footprint is sorted by the existing `EntityRef` ordering and deduplicated before encoding.
- A deployment footprint MUST contain at least the chain, wallet, and deployer/sender entities. A call footprint MUST contain at least the chain, sender wallet, and target contract; token, spender, router, pool, callback, deployer, provider, and strategy entities are added when present in the operation.
- No unknown trailing fields are accepted.

The Rust implementation MUST expose:

```rust
impl CanonicalWire for EvmTransactionIntent {
    const KIND: u8 = EVM_TRANSACTION_INTENT_KIND;

    fn canonical_bytes(&self) -> Vec<u8> {
        // exact field order above; no JSON serialization
    }
}
```

## 6. Typed WalletCoreGate protocol

The Python/Elixir-facing protocol is a typed transport contract, not a boolean callback:

```python
class WalletCoreGate(Protocol):
    def simulate(
        self,
        request: EvmIntentRequest,
    ) -> SimulationTicket:
        ...

    def authorize_signing(
        self,
        ticket: SimulationTicket,
    ) -> SigningAuthorization:
        ...

    def authorize_broadcast(
        self,
        authorization: SigningAuthorization,
        signed_transaction: SignedEvmTransaction,
    ) -> BroadcastPermit:
        ...
```

The Python objects are transport DTOs only. Rust is authoritative for validation, canonical encoding, registry reads, policy evaluation, and signing.

### Request

```python
@dataclass(frozen=True)
class EvmIntentRequest:
    intent: EvmTransactionIntentDto
    init_code: bytes | None
    request_id: str
    caller_principal: str
```

`init_code` is accepted only for deployment and is used to recompute the init-code hash. The caller does not provide a hash that wallet-core blindly trusts.

### Simulation ticket

```python
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
    nonce: bytes  # 16 random bytes for the BWAU context
```

The ticket MUST be authenticated by the Rust wallet-core service. A Python caller MUST NOT be able to construct a valid ticket by filling these fields locally.

`simulation_hash` is a digest of the deterministic simulation result, including the exact canonical payload and relevant chain-state inputs. A placeholder such as `simulation:<id>@<version>` is not acceptable for production.

### Signing authorization

```python
@dataclass(frozen=True)
class SigningAuthorization:
    ticket: SimulationTicket
    authenticated_envelope: bytes  # BWAU envelope
    signer_key_id: str
    registry_version: int
    intent_digest: bytes
    signer_binding: bytes
    raw_signed_transaction: bytes
```

The production implementation should keep `raw_signed_transaction` inside the wallet-core/chain-adapter boundary and expose an opaque handle instead of raw bytes to higher-level callers. If raw bytes cross the boundary, they MUST be immediately revalidated against the ticket and MUST NOT be persisted in ordinary logs.

### Broadcast permit

```python
@dataclass(frozen=True)
class BroadcastPermit:
    intent_id: str
    intent_digest: bytes
    registry_version: int
    signer_key_id: str
    permit: bytes
```

`authorize_broadcast` MUST perform the final wallet-core registry snapshot and deny if the version differs from the ticket or any footprint entity is quarantined. Only after that check may the chain adapter call `eth_sendRawTransaction`. The adapter then validates the receipt and creates the public deployment/broadcast record.

## 7. BWAU authenticated envelope binding

The existing authenticated envelope is used without modification:

```text
magic       = "BWAU"
auth_version = 1
kind        = 7
signer      = Rust wallet-core signer identity
key_id      = approved signer key identifier
subject     = wallet/agent subject
registry_version
expires_at_unix
nonce       = 16 random bytes
payload     = exact BW3C EvmTransactionIntent bytes
payload_hash = SHA-256(kind || payload)  // BWAU's existing payload_digest rule
signature
```

The signed message remains the existing `AuthenticatedEnvelope::signed_message()` construction. The signature MUST cover the payload hash, signer, key ID, subject, registry version, expiry, nonce, authentication domain, and authentication version.

### Python transport authentication extension

The generic BWAU v1 envelope intentionally remains wire-compatible. Because a
`SimulationTicket` also carries request identity, policy/capability identity,
wallet identity, and the deterministic simulation result, wallet-core signs a
second, versioned ticket transcript with the same registered Ed25519 key. The
Python DTO carries this as `ticket_signature`; the transcript is exposed by
Rust as `ticket_binding_message()` and is encoded as:

```text
domain = "BOOTSTRAP-WALL3T/AUTHENTICATED-TICKET/V1\\0"
u16 transcript_version = 1
u64 chain_id
str request_id, str intent_id
u16 wire_version, u8 record_kind
bytes canonical_payload
[32] intent_digest
u64 registry_version
[32] simulation_hash
str policy_id, str capability_id, str wallet_id
str signer_key_id, str subject
u64 expires_at_unix
[16] nonce
```

The Python verifier MUST receive a trusted, public-key-only registry through
configuration or dependency injection. It MUST NOT accept a public key,
signer mapping, or algorithm choice from the ticket. It verifies both the BWAU
signature and `ticket_signature`, and rejects any mismatch in the complete
transcript before returning `ValidatedSimulationTicket`.

The verifier MUST reject:

- an envelope whose payload header is not `BW3C`, version 1, kind 7;
- a payload hash mismatch;
- a registry version mismatch;
- an expired envelope;
- a reused nonce/request ID;
- an unapproved signer key ID;
- a signer not authorized for the wallet/principal;
- a payload whose `from`, chain, target, value, calldata, code hash, or policy binding differs from the requested action.

## 8. Required lifecycle

```text
1. Build typed EvmTransactionIntentRequest.
2. Wallet-core validates all fields and derives the complete footprint.
3. Wallet-core computes exact BW3C bytes and the `intent_digest`; BWAU adds its distinct envelope `payload_hash`.
4. Wallet-core reads authoritative quarantine/policy state.
5. Wallet-core simulates the exact transaction and returns an authenticated ticket.
6. Wallet-core rechecks the ticket at signing.
7. Rust wallet-core signer signs exactly the ticket-bound transaction.
8. Wallet-core rechecks the registry and signed transaction at broadcast.
9. Chain adapter submits the exact signed transaction.
10. Receipt is matched to intent ID, chain ID, sender, target/deployment, and payload hash.
```

Any failure is a deny outcome. There is no fallback to the old generic `authorize()` method.

## 9. Exact binding checks before signing and broadcast

The gate and adapter MUST compare the following values byte-for-byte or as typed integers:

| Field | Request | BW3C payload | Signed tx / RPC action |
|---|---:|---:|---:|
| Chain ID | yes | yes | yes |
| Sender | yes | yes | recovered/verified |
| Wallet identity | yes | yes | signer binding |
| Principal/agent | yes | yes | policy ticket |
| Operation | yes | yes | deploy vs call |
| Target | yes | yes | tx `to` |
| Nonce | yes | yes | signed tx |
| Value | yes | yes | signed tx |
| Gas limit | yes | yes | signed tx |
| Fee model and values | yes | yes | signed tx |
| Calldata | yes | yes | signed tx data |
| Init code | yes | hash | signed deployment data |
| Artifact/source digest | yes | yes | approved registry |
| Policy/capability/document | yes | yes | wallet-core ticket |
| Footprint | derived | yes | final barrier |
| Registry version | yes | authenticated context | final barrier |
| Expiry/nonce | yes | authenticated context | replay protection |

The signer MUST NOT be called until all request-to-payload comparisons succeed. The ticket's `intent_digest` MUST equal `SHA-256(canonical_bw3c_bytes)`, while the BWAU envelope's `payload_hash` MUST equal the existing `SHA-256(kind || payload)` calculation.

## 10. Rejection conditions

The implementation MUST reject:

- generic operation-only authorization requests;
- caller-provided payload hashes that were not computed by wallet-core;
- mismatched source or bytecode hashes;
- deployment requests with a non-empty `to` address;
- contract calls without a target;
- unknown language or fee discriminants;
- non-canonical address casing or malformed addresses;
- zero or overflowing quantities where disallowed by policy;
- expired or not-yet-valid tickets;
- stale registry versions;
- changed calldata, value, nonce, sender, gas, or fees after simulation;
- signer key IDs not assigned to the wallet/principal;
- a final registry read that is unavailable;
- any unknown trailing bytes in the BW3C payload;
- replayed request IDs or BWAU nonces.

## 11. Migration from the current adapter

The current methods:

```python
adapter.deploy(artifact, from_address)
adapter.read_domain(address, language)
adapter.validate_version(address, language, expected, current)
```

should be split into:

```python
ticket = gate.simulate(EvmIntentRequest(...))
authorized = gate.authorize_signing(ticket)
broadcast = gate.authorize_broadcast(authorized, signed_transaction)
```

Read-only calls may use a lighter `ReadAuthorization` containing a canonical call intent and registry version, but they must still reject unknown languages and must not be used as a substitute for write authorization.

The adapter MUST delete or deprecate the generic `authorize(operation, chain_id, contract)` method after the typed protocol is available. A compatibility shim, if temporarily required, MUST raise an explicit `UnsupportedLegacyAuthorization` error rather than silently accepting the old flow.

## 12. Acceptance tests

The implementation is not complete until tests prove:

1. Changing one bit of bytecode changes `init_code_hash`, BW3C bytes, `intent_digest`, and signature input.
2. Changing one calldata byte invalidates the signing ticket.
3. Changing sender, target, value, nonce, chain ID, gas, or fee invalidates the ticket.
4. Changing policy, capability, document, principal, or footprint invalidates the ticket.
5. A quarantine update between simulation and signing is denied.
6. A quarantine update between signing and broadcast is denied.
7. A registry reversal invalidates an old positive ticket.
8. A mismatched signer key ID is denied.
9. A replayed BWAU nonce or request ID is denied.
10. Solidity and Vyper artifacts with different bytecode/source hashes cannot substitute for each other.
11. The final signed transaction fields exactly match the ticket.
12. Rust, Elixir, TypeScript, and Python consumers produce identical BW3C bytes for the same fixture.
13. Unknown versions, kinds, discriminants, malformed lengths, trailing bytes, and non-canonical addresses are rejected.

A shared fixture should include the exact BW3C bytes, payload SHA-256, BWAU signed-message bytes, and all typed field values. The fixture MUST contain no private keys or live credentials.

## 13. Implementation boundary

This design resolves the authorization-binding flaw, but it does not itself claim that the current repository already implements it. The following remain implementation tasks:

- Add `EvmTransactionIntent` and kind 7 to Rust wallet-core.
- Add strict EVM address/U256 validation and canonical encoding.
- Add authenticated ticket issuance and verification over the existing BWAU envelope.
- Bind the Rust signer to the ticket and exact transaction digest.
- Expose a transport adapter for Python/Elixir that carries typed DTOs and opaque tickets.
- Replace the current generic Python callback.
- Add cross-language BW3C fixtures and exact-byte tests.
- Add final read-barrier and receipt-binding tests.

Until those tasks are complete, the EVM adapter remains a prototype and must not be used for real-value signing or deployment.

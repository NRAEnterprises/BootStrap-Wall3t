# Phase 1 Domain Contracts

**Status:** foundation implemented; integration and durable storage remain open.

The first Phase 1 executable slice lives in `rust/wallet-core/src/domain.rs`. It is dependency-free and validation-heavy so the Elixir orchestration layer can carry opaque identifiers and policy decisions without becoming a key, funding, policy, or quarantine authority.

## Module coverage

### 1.1 User/agent wallet graph

The contract defines opaque `UserWalletId`, `AgentWalletId`, `PolicyId`, `FlowId`, `CapabilityId`, and `DocumentHash` values. `UserWallet`, `AgentWallet`, and `AgentAssignment` capture ownership, status, scopes, policy binding, and revocation. `FundingAuthorization` explicitly rejects an agent-to-user funding direction and self-funding. The model supports multiple scoped assignments while keeping the parent-wallet boundary outside agent authority.

The current slice does not persist a graph or expose a management API. It proves the domain invariants in memory and is ready for an Elixir/Rust transport adapter.

### 1.2 Three-vault contract

`VaultKind` separates `Secrets`, `Automations`, and `FinancialCold`. `VaultPolicy::validate` rejects raw Secrets access by the browser, Elixir, or agents; requires Rust wallet-core at the signer boundary; rejects cold-storage or hardware semantics on the Automations Vault; and requires cold storage, user hardware authorization, and a non-zero withdrawal delay for the Financial Cold Vault. Agents and Elixir cannot be principals on the Financial Cold Vault.

The contract intentionally does not choose HashiCorp Vault, KMS, HSM, or a hardware vendor. Storage and cryptographic implementation are Phase 2/5 work.

### 1.3 Policy and automation-flow schema

`AutomationPolicy` binds an owner wallet, agent wallet, non-empty chain/venue/contract/asset scope, budget, retry policy, execution mode, document hash, and capability ID. `EmergencyPaused` and zero-attempt retry policies fail closed. There is no per-transaction approval field: autonomous operation is represented by explicit policy mode and capability scope.

`AutomationFlow` binds a policy and agent, requires a content hash, and requires every step to include an operation and non-empty `EntityRef` footprint. The existing wallet-core pipeline remains the final authority for quarantine, simulation, signing, and broadcast.

### 1.4 Global blacklist/quarantine event contract

`QuarantineEvent` adds a typed event envelope around an entity subject, monotonic registry version, reason, `EvidenceProvenance`, reporter, propagation acknowledgements, and optional user reversal authorization reference. Validation rejects stale/non-monotonic versions, empty reasons, invalid evidence provenance, unknown propagation wallets, and zero IDs. Acknowledgement sets must be subsets of the expected linked-wallet set.

The event contract does not grant agents reversal authority. Cryptographic WebAuthn validation, durable replication, and atomic persistence remain Phase 2 work.

## Evidence

The module adds seven focused Rust tests. Together with the existing wallet-core tests, the workspace currently passes **28 tests**: 19 unit tests and 9 public-API integration tests. `cargo clippy --workspace --all-targets -- -D warnings` is clean.

## Remaining Phase 1 work

The foundation is not a complete Phase 1 exit. Remaining work includes a persistent wallet-graph repository, Elixir transport/serialization adapters, canonical wire-format hashes, a concrete vault access service, policy document persistence, propagation integration with the authoritative registry, and cross-language contract tests. These must be implemented before marking Modules 1.1–1.4 complete.

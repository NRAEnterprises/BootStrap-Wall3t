# BootStrap Wall3t — Core Architecture Verification

**Review date:** 2026-11-20
**Plan reviewed:** `docs/BUILD_PLAN.md` at the local review branch
**Scope:** full-autonomy model, three vault boundaries, global automatic blacklist/quarantine

## Executive result

The finalized architecture is **aligned with the full-automation requirement** after removing residual per-transaction approval language from the plan. The intended interaction model is now:

- the user creates/funds agent wallets and installs policies, strategy documents, and operating configurations;
- agents execute autonomously inside their own funded-wallet boundary;
- ordinary transactions do not require user prompts or continuous supervision;
- agents cannot debit, borrow from, or derive authority from the parent wallet;
- the user has supervisory visibility and can configure, revoke, pause, fund, or replace policies;
- quarantine is a mandatory wallet-core deny mechanism and is not a human approval workflow.

The architecture is **not yet implemented in the repository**. The current GitHub-era Python code contains only a prototype `ThreatRegistry` check in the swap helper. It does not implement the three-vault model, the Rust trust boundary, global multi-operation quarantine enforcement, user-only unquarantine, or authoritative cross-wallet state propagation.

The correct status is therefore:

| Area | Architecture status | Executable implementation status |
|---|---|---|
| Full autonomous execution | Aligned | Not implemented in the remake; prototype only |
| Parent-to-agent isolation | Specified | Not implemented |
| Secrets Vault | Specified | Not implemented as the finalized three-vault boundary |
| Automations Vault | Specified | Prototype Python vault exists, but its contents and boundary do not match the finalized model |
| Financial Cold Vault | Specified | Not implemented |
| Global automatic blacklist | Specified | Partial prototype only |
| User-only unquarantine | Specified | Not implemented |
| All-operation quarantine gates | Specified | Not implemented |

No production-readiness claim should be made until the implementation rows are backed by code, integration tests, and audit evidence.

### Update — 2026-11-20, Rust foundation drafted

`rust/wallet-core` now implements the registry contract, entity scopes, intent footprint, three-stage trust pipeline, and the first Phase 1 domain-contract foundation. Verification: 28 passing tests (19 unit, 9 public-API integration) and a clean `cargo clippy --workspace --all-targets -- -D warnings` run. The status table above is superseded as follows:

| Area | Architecture status | Executable implementation status |
|---|---|---|
| Full autonomous execution | Aligned | Pipeline supports it; no workflow runtime yet |
| Parent-to-agent isolation | Specified | Phase 1 contract rejects agent-to-parent funding; persistent graph and service boundary pending |
| Secrets Vault | Specified | Phase 1 policy validation rejects UI/Elixir/agent access; storage service pending |
| Automations Vault | Specified | Phase 1 typed policy boundary exists; persistence and service enforcement pending |
| Financial Cold Vault | Specified | Phase 1 policy requires cold storage, hardware authorization, and delay; custody service pending |
| Global automatic blacklist | Specified | Reference registry/guard and Phase 1 typed event envelope implemented; durable store and propagation transport pending |
| User-only unquarantine | Specified | Enforced by contract type; cryptographic hardware verification pending |
| All-operation quarantine gates | Specified | One shared guard covers all operation kinds; chain adapters pending |

Details and deliberate limits are recorded in `docs/RUST_WALLET_CORE.md`.

## 1. Architecture alignment review

### Full automation

The build plan now correctly states that policies are machine-enforced operating definitions, not approval requests. The policy may define asset, chain, contract, schedule, trigger, execution mode, and optional user-selected limits. The platform must not add a mandatory per-transaction approval queue or impose a universal loss cap that the user did not choose.

The non-negotiable technical boundaries are custody boundaries:

1. An agent can operate autonomously with assets held by its own wallet.
2. An agent cannot reach the parent wallet or Financial Cold Vault.
3. The parent wallet can observe agent state through a one-way supervisory view.
4. The user can create, fund, configure, revoke, pause, or replace authority, but does not need to approve ordinary execution.
5. Global quarantine is an automatic deny rule that every agent must obey.

### Three vaults

The separation is structurally sound only if it is enforced as separate principals and APIs, not merely as three folders or namespaces.

| Vault | May contain | Allowed callers | Must not do |
|---|---|---|---|
| Secrets Vault | Private keys, mnemonics, API keys, OAuth tokens, SSH keys, auth/signing material | Rust signer boundary and narrowly scoped credential adapters | Expose raw contents to UI, Elixir, or agents; store policies as authority |
| Automations Vault | Policies, strategy/document packages, loop configs, triggers, schedules, prompts, discovery rules | Policy compiler, Elixir orchestrator, policy UI | Sign, unlock, transfer, or grant parent-wallet authority |
| Financial Cold Vault | User long-term crypto and supported fiat/fiat claims, hardware-generated keys, staking positions | User/hardware authorization path | Be accessible to agents; permit immediate or agent-initiated withdrawals |

A storage provider such as HashiCorp Vault, a cloud KMS, an HSM, or a hardware wallet is an implementation choice. The security boundary is defined by access authority and callable operations, not by the vendor name.

## 2. Global blacklist/quarantine contract

### Required state model

The registry must use a monotonic, versioned deny state. A quarantine record should include:

```text
quarantine_id
registry_version
scope_type: token | contract | deployer | pair | chain | provider | strategy_family
chain_id
canonical_identifier
reason_code
evidence_refs
reported_by: user | agent_id
created_at
status: ACTIVE | REVERSED
reversal_version
reversed_by: user_identity
```

The canonical identifier must be normalized by chain and entity type. A symbol alone is never sufficient because symbols are spoofable and non-unique.

### Required propagation model

Agents do not need peer-to-peer communication. The implementation needs one authoritative source of deny state and a mechanism that makes stale local state fail closed:

1. A user or agent submits a signed quarantine request.
2. The quarantine service validates the reporter and canonical identifier.
3. The service atomically appends a new registry version.
4. Linked wallets receive the new deny state through a push stream, shared local state, or signed replicated snapshot.
5. Each wallet invalidates positive allowlist/quote/strategy caches.
6. The Rust wallet core checks the registry version and entity match immediately before simulation, immediately before signing, and immediately before broadcast where a broadcast path exists.
7. If the snapshot is stale, unavailable, unverifiable, or inconsistent, the affected operation is rejected.
8. Only a user-authorized hardware-backed reversal can create a reversal version. An agent cannot remove or override an active entry.

“Simultaneously” means no linked wallet may continue an affected write based on an old positive decision after the new registry version is committed. A distributed system cannot promise identical physical timing, so the enforceable invariant is versioned deny-before-write with stale-state rejection.

### Operation coverage matrix

Every operation that can move value, create a standing permission, or activate an automated strategy must pass the same `QuarantineGuard` contract. The check must cover both direct assets and reachable contracts/dependencies discovered during construction.

| Operation | Required quarantine targets | Required check points |
|---|---|---|
| Native transfer | destination chain, destination contract if applicable, sender/recipient policy scopes | intent admission, pre-sign, pre-broadcast |
| Token transfer | token contract, recipient contract, deployer if known | intent admission, simulation, pre-sign, pre-broadcast |
| ERC-20 approve | token contract, spender contract, pair/venue if mapped | calldata decode, simulation, pre-sign, pre-broadcast |
| Permit / Permit2 / EIP-2612 | token, spender, permit domain chain, referenced operator | typed-data admission, pre-sign, submission path |
| NFT approval / `setApprovalForAll` | collection, operator, marketplace/contract | calldata decode, simulation, pre-sign, pre-broadcast |
| Swap | input token, output token, router, pools, callback/dependency contracts, deployer | route construction, simulation, pre-sign, pre-broadcast |
| Bridge | source token, bridge contracts, destination token/contract, relayer/provider | route construction, source simulation, pre-sign, destination submission |
| Staking / delegation | staking contract, validator/operator, token, reward contract | intent admission, simulation, pre-sign, pre-broadcast |
| Agent-to-agent transfer | destination agent wallet, destination chain, asset, receiving contract | policy admission, pre-sign, pre-broadcast |
| Lightning payment | invoice destination, node/provider, payment hash context, asset scope | invoice decode, policy admission, pre-send |
| Bootstrap method | every resulting destination, payment endpoint, token/contract touched | workflow trigger, action construction, pre-sign/pre-send |
| Discovery-triggered action | discovered target, token/contract/deployer/pair, data-provider scope | candidate admission, policy activation, action construction |
| Strategy activation | strategy capsule hash, target scope, referenced venues/assets/chains | trigger admission, policy resolution, every generated action |
| Cold-vault withdrawal | destination and asset only; quarantine cannot make a cold withdrawal agent-accessible | user/hardware authorization and final release gate |

A single pre-trade check in a swap helper is insufficient. The guard belongs in the Rust wallet-core execution pipeline, below individual agent workflows, so new agent types cannot accidentally bypass it.

## 3. Required implementation interfaces

The remake should define interfaces equivalent to:

```text
QuarantineRegistry::current_version() -> RegistryVersion
QuarantineRegistry::is_denied(EntityRef, version) -> DenyDecision
QuarantineRegistry::submit_report(AuthenticatedReporter, QuarantineEvidence) -> RegistryVersion
QuarantineRegistry::reverse(UserHardwareAuthorization, QuarantineId) -> RegistryVersion
QuarantineGuard::check(IntentFootprint, RequiredRegistryVersion) -> Result<(), Denied>
```

Every `Intent` should produce an `IntentFootprint` containing all assets, chains, contracts, spenders, venues, operators, providers, and destination entities that could be affected. The wallet core checks the footprint rather than relying on an agent to remember individual token checks.

The result must be fail-closed and typed, for example:

```text
Allowed { registry_version }
Denied { quarantine_id, entity, reason, registry_version }
StaleRegistry { required_version, observed_version }
UnavailableRegistry { retry_after, affected_scope }
UnverifiableEntity { entity, reason }
```

## 4. Acceptance tests

The minimum implementation evidence must include:

1. Agent A reports a bad token; Agent B, Agent C, and the user wallet reject it without peer messaging.
2. A quarantine committed between simulation and signing causes signing to fail.
3. A quarantine committed between signing and broadcast causes broadcast to fail or the transaction to be withheld according to the chain adapter contract.
4. A stale or unavailable registry blocks affected writes but does not require a human approval prompt.
5. A token quarantine blocks token transfer, approval, permit, swap, bridge, staking, and strategy-generated actions.
6. A router/contract/deployer quarantine blocks a swap even when both tokens are not quarantined.
7. A pair or strategy-family quarantine blocks matching route/template execution.
8. An agent cannot reverse or delete a quarantine entry.
9. The user can reverse a quarantine only with the required user/hardware authority, creating a new registry version and audit event.
10. Reversal does not restore old positive cache entries or bypass current policy/contract checks.
11. A new agent created after a quarantine receives the active deny state before it can execute.
12. The Financial Cold Vault remains inaccessible to agents even when an agent has broad autonomy over its own funded wallet.
13. Discovery and bootstrap workers cannot directly sign or broadcast; their generated intents still pass through the same guard.
14. All operation types in the coverage matrix are tested with at least one malicious fixture and one registry race.

## 5. Current blockers

The current repository still contains prototype behavior that must not be treated as this architecture’s implementation:

- `ThreatRegistry` is file-backed Python state with a local reload and a swap-focused call path; it is not a globally versioned, signed, user-reversible quarantine service.
- The prototype does not place blacklist enforcement below all agent operation types.
- The prototype accepts mnemonics through an HTTP request and uses mock signing/broadcasting; it cannot serve as the Secrets Vault or Rust signer implementation.
- The three finalized vault boundaries do not yet exist as separate services, principals, or policy-enforced APIs.
- The Financial Cold Vault, hardware withdrawal delay, and user-only reversal workflow are design requirements only.

## Verification conclusion

The plan is now aligned with full automation, but implementation verification is **FAIL / not yet implemented** for the three-vault system and global automatic quarantine. The next implementation milestone must build the domain model and Rust `QuarantineGuard` before adding more agent operation types. No existing Python prototype path should be promoted into production by documentation alone.

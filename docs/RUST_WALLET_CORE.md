# Rust Wallet Core — Quarantine Registry and Trust Boundary

**Status:** implementation draft, verified locally on 2026-11-20
**Crate:** `rust/wallet-core` (`bootstrap-wall3t-wallet-core`)
**Verification:** `cargo test --all-targets` → 21 passing tests; `cargo clippy --all-targets -- -D warnings` clean

This module is the first executable piece of the finalized architecture. It exists so the global quarantine requirement is enforced by a trust boundary rather than by a per-workflow check that a new agent type can forget.

## What it implements

### `QuarantineRegistry` — authoritative versioned deny state

- `snapshot()` returns the current `RegistryVersion` plus every active record.
- `publish()` accepts a reporter (user or agent), an `EntityRef`, a reason code, and evidence references. It atomically increments the version and returns the created record.
- `reverse()` requires `UserHardwareAuthorization` (identity plus hardware assertion) and a record id. It increments the version, marks the record inactive, and records the reversal version and identity.
- Invalid evidence (empty reason or no evidence references) is rejected **without** advancing the version.
- An unknown record id is rejected **without** advancing the version.

`InMemoryQuarantineRegistry` is a reference implementation of this contract. It is linearizable within a process because every read and write takes the same `RwLock`, but it is **not** the production registry. Production requires a durable, replicated, signed store with the same monotonic version semantics.

### `EntityRef` — canonical quarantine scope

Supported scopes: `Token`, `Contract`, `Deployer`, `Pair`, `Chain`, `Provider`, `StrategyFamily`, `Wallet`. Each carries a chain id except `StrategyFamily`. Addresses are normalized strings; the production implementation must canonicalize checksums, case, and chain-specific address formats before comparison, and must never match on symbol alone.

### `IntentFootprint` — everything an intent could touch

An intent footprint is the sorted, deduplicated set of entities an operation can affect: assets, contracts, spenders, routers, pools, callbacks, deployers, validators, providers, destination wallets, and strategy families. The guard checks the footprint, not a hand-picked subset of fields, so router-only, deployer-only, and pair-only compromises are covered.

### `WalletCore` — three-stage trust pipeline

```text
simulate(intent) -> SimulationTicket { intent, registry_version, simulation_hash }
sign(ticket)     -> SignedIntent    { ticket, signature }
broadcast(signed)-> BroadcastReceipt { intent_id, registry_version, transaction_id }
```

Each stage:

1. reads the current registry snapshot;
2. rejects the operation if the ticket's version differs from the current version (`StaleRegistry`);
3. re-evaluates the footprint against active records (`Quarantined`);
4. fails closed if the registry is unavailable.

A registry version change of any kind — including a **reversal** — invalidates outstanding tickets. That is intentional: a positive decision is never reusable across a version boundary, which removes the time-of-check/time-of-use window that a cached allowlist would otherwise create.

The signer is behind the `OpaqueSigner` trait. `WalletCore` never handles key material; the test signer is a deterministic stub for the test suite only and must not ship.

## Failure taxonomy

`TrustError` distinguishes `Registry(RegistryError)`, `StaleRegistry { ticket, current }`, `Quarantined { entity, quarantine_id, registry_version }`, `InvalidIntent`, and `SigningUnavailable`. All are deny outcomes. None of them convert into a human approval prompt, which is what keeps the automation model intact.

## Test coverage

Unit tests in `src/lib.rs` (12):

- an agent's report denies another agent without peer messaging;
- empty or missing hardware authorization cannot reverse a quarantine;
- publishing any record makes an existing simulation ticket stale;
- signing and broadcast each recheck the footprint after the previous stage;
- a quarantined router blocks a swap whose two tokens are clean;
- all eleven `OperationKind` variants pass through the same guard;
- concurrent reporting races against signing and against broadcast;
- a reversal also invalidates pre-existing positive tickets;
- empty intents fail closed;
- an unavailable registry blocks admission.

Integration tests in `tests/quarantine_races.rs` (9) exercise the public API only:

- one agent report denies a second agent and the user wallet;
- a newly created agent inherits active quarantine at admission;
- a chain-scope quarantine blocks other operations on that chain;
- reversal requires a fresh ticket before execution resumes;
- an approval quarantined between signing and broadcast is withheld;
- a strategy-family quarantine blocks template execution;
- invalid evidence and unknown reversal ids do not advance the version;
- a forged ticket version is rejected.

## Deliberate limits

- No chain adapter, RPC client, or real signing exists here. `BroadcastReceipt.transaction_id` is synthetic.
- No persistence, replication, or signature verification on registry records yet; those belong to the production adapter and are the next gate.
- Address normalization is caller-supplied. Production must canonicalize per chain.
- The registry does not yet enforce that an agent may not reverse its own report beyond the type-level requirement for user hardware authorization; the production service must authenticate that assertion cryptographically.
- Discovery and bootstrap workers are not implemented; when they are, they must submit `TxIntent` values rather than calling a signer directly.

## Running it

```bash
cd rust
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

The crate has no external dependencies, so it builds offline once a toolchain is present.

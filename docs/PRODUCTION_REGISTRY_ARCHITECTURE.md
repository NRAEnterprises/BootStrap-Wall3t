# BootStrap Wall3t — Production Quarantine Registry Architecture

**Status:** design draft following the Rust reference implementation
**Scope:** durable storage, replication, signed state, freshness, cache invalidation, and wallet-core integration
**Non-goal:** this document does not make the in-memory registry production-ready by adding persistence alone

## 1. Design conclusion

Replace `InMemoryQuarantineRegistry` with a dedicated **Quarantine Registry Service** implemented in Rust and backed by a quorum-replicated append-only log. The wallet core never trusts an unsigned row, an unboundedly stale replica, or a local allow cache.

The production contract is:

```text
reporter -> authenticated registry write -> quorum commit
         -> monotonic registry version
         -> signed checkpoint + state root
         -> replica fan-out / cache invalidation
         -> wallet-core read barrier before each write stage
```

A quarantine report is acknowledged only after it is durably committed by a quorum. A wallet-core operation is executable only when it has a valid, authenticated registry proof at or beyond the operation's required version and the proof does not deny any entity in the intent footprint.

A signed checkpoint proves what the registry says. A read barrier proves the wallet is not relying on a known-stale checkpoint. The final sign and broadcast gates require the read barrier; an offline cached checkpoint is never sufficient for a value-moving write.

## 2. Security and consistency invariants

### Safety invariants

1. **Monotonicity:** every committed registry command has exactly one increasing `RegistryVersion`; no failed command advances it.
2. **Single history:** committed nodes agree on the command sequence and state root. Forked or conflicting histories are rejected.
3. **Deny-before-write:** after a quarantine command is committed, a linked wallet cannot sign a matching intent using an older positive decision.
4. **Deny-overrides:** quarantine overrides policies, allowlists, discovery results, cached quotes, strategy templates, and local agent configuration.
5. **User-only reversal:** only a verified user hardware authorization can append a reversal command. Agents may submit reports but cannot reverse, expire, or weaken them.
6. **Fail closed:** unavailable, stale, unverifiable, inconsistent, or expired state blocks affected writes; it never falls back to the last positive decision.
7. **No peer messaging dependency:** agents never need to communicate with one another for enforcement. They report to the registry; wallet core consumes the shared state.
8. **Auditability:** every command, checkpoint, proof, decision, and reversal is attributable and hash-linked without storing private key material.

### Consistency boundary

The phrase “simultaneously across every wallet” is implemented as a linearizable deny-before-write invariant, not an impossible promise of identical network timing. A wallet may be temporarily unable to learn a newly committed entry, but it must then fail its read barrier and stop affected writes. It may not continue using a stale positive decision.

## 3. Components

```text
                         +----------------------------+
                         |  Quarantine Registry API   |
                         |  authenticated Rust service |
                         +-------------+--------------+
                                       |
                         +-------------v--------------+
                         |  Raft / quorum commit log  |
                         |  3 nodes minimum, 5 normal |
                         +------+------+---------------+
                                |      |
                +---------------+      +----------------+
                |                                     |
       +--------v---------+                  +--------v---------+
       | State materializer |                  | Evidence store   |
       | active deny index  |                  | immutable blobs  |
       +--------+---------+                  +------------------+
                |
       +--------v---------+
       | Signed checkpoint |
       | state root + head |
       +--------+---------+
                |
       +--------v---------+
       | Wallet-core read  |
       | barrier / guard   |
       +-------------------+
```

### Registry API service

The API service is the only component allowed to append quarantine commands. It authenticates reporters, canonicalizes entity identifiers, validates evidence metadata, verifies user hardware authorizations for reversals, and submits deterministic commands to the consensus log.

It does not directly mutate a database row outside the committed state machine. Every mutation is a command with an idempotency key and a deterministic result.

### Replicated commit log

Use a 3-node minimum / 5-node normal Raft group or an equivalent Byzantine-resistant service only if the threat model requires Byzantine storage nodes. The initial recommended model assumes authenticated, operator-controlled nodes with independent failure domains:

- quorum commit requires 2 of 3 or 3 of 5 voting members;
- the log index is the `registry_version`;
- every command contains the previous log hash and expected head version;
- snapshots are produced only from committed log prefixes;
- a leader lease is used for low-latency reads, but final wallet-core barriers require a committed-head proof or quorum read;
- compaction retains signed checkpoints and enough command history for audit and replay.

A plain primary/replica database replication setup is not sufficient by itself unless its commit protocol provides the same linearizable write and read-barrier guarantees.

### State materializer

The deterministic state machine applies commands to an active deny index. It stores both the current active record and the event history:

```text
QuarantineState {
  registry_version,
  previous_state_root,
  state_root,
  active_records_by_canonical_entity,
  record_status,
  last_command_hash,
}
```

The active index is an optimization. The event log and signed state root remain the source of audit truth.

### Evidence store

Evidence blobs live outside the consensus log in immutable, content-addressed storage. The log stores only hashes, type, size, retention class, origin, and access policy. Evidence may include provider observations, transaction ids, bytecode hashes, simulation traces, agent reports, and user review records.

A missing evidence blob does not reactivate an entry. Evidence deletion or retention expiry creates an audit event and cannot mutate the active deny state.

### Signed checkpoint service

After each committed batch, the registry signs a checkpoint:

```text
Checkpoint {
  domain = "bootstrap-wall3t/quarantine/checkpoint/v1",
  cluster_id,
  registry_id,
  version,
  previous_checkpoint_hash,
  log_head_hash,
  state_root,
  committed_at,
  fresh_until,
}
```

The checkpoint is signed by a registry signing key held in an HSM or equivalent signing service. The checkpoint also carries a quorum certificate: signatures from the required voting members over the same checkpoint hash, or a consensus-system proof that is independently verifiable by the wallet-core adapter.

A signature authenticates the state, not freshness. Therefore the wallet core requires either:

- a current quorum read barrier for signing/broadcast; or
- an unexpired, bounded-freshness certificate issued under a documented emergency policy that still fails closed when its lease expires.

The recommended production default is the quorum read barrier for every sign and broadcast gate.

## 4. Data model and canonicalization

### Canonical entity identifiers

The service accepts typed identifiers only:

```text
CanonicalEntity {
  scope_type,
  chain_id,
  normalized_identifier,
}
```

Rules:

- symbols, names, URLs, and display labels cannot be the sole identifier;
- EVM addresses are normalized to 20-byte lowercase bytes after checksum validation;
- transaction and block identifiers are chain-scoped;
- Solana, Bitcoin, Fuel, and Lightning identifiers use chain-native parsers;
- provider and strategy-family ids use a registered namespace plus normalized name;
- pair ids include chain, venue, and canonical asset ordering;
- deployer records use the verified creator address plus chain;
- an alias may aid search but never replaces the canonical id.

### Commands

```text
PublishQuarantine {
  command_id,
  expected_version,
  reporter_identity,
  entity,
  reason_code,
  evidence_refs,
  submitted_at,
  reporter_signature,
}

ReverseQuarantine {
  command_id,
  expected_version,
  quarantine_id,
  user_identity,
  hardware_authorization,
  evidence_review_hash,
  submitted_at,
}
```

Both commands are idempotent by `command_id`. Reusing a command id with different canonical bytes is rejected. `expected_version` prevents an operator from silently applying a reversal or report against an unseen head.

### State-root construction

Use a deterministic Merkle map keyed by the canonical entity bytes. Each active leaf commits to:

```text
leaf = H(
  domain || quarantine_id || registry_version || entity ||
  reason_code || evidence_hashes || reporter || created_at || status
)
```

The state root makes a checkpoint compact and lets a wallet or auditor verify an inclusion/exclusion proof. The wallet core must still obtain a read barrier for final writes; an inclusion proof alone cannot establish that the proof is current.

## 5. Wallet-core integration

Replace the current trait implementation with methods equivalent to:

```text
RegistryClient::read_barrier(min_version) -> Result<CertifiedSnapshot, RegistryError>
RegistryClient::submit_report(AuthenticatedReporter, Evidence) -> Result<CommitReceipt, RegistryError>
RegistryClient::reverse(UserHardwareAuthorization, QuarantineId) -> Result<CommitReceipt, RegistryError>
RegistryClient::subscribe(from_version) -> Stream<CheckpointEvent>

QuarantineGuard::check(footprint, certified_snapshot) -> Result<Allowed, Denied>
```

### Stage behavior

- **Simulation:** may use a certified snapshot, but records its version and state root in the ticket.
- **Signing:** obtains a new read barrier at least at the ticket version, rejects any version mismatch, verifies the checkpoint/quorum certificate, then checks the footprint.
- **Broadcast:** obtains a final read barrier and repeats the same checks. A chain adapter must not accept an already signed payload if the registry barrier fails.
- **Subscription:** updates local indexes and invalidates all positive policy, quote, route, discovery, and strategy caches on every committed version. Subscription lag never authorizes a write.

### Registry outage behavior

The wallet core may continue read-only dashboards from the last verified checkpoint. It may continue non-financial local computation. It must reject simulation tickets for execution, signing, broadcast, approvals, permits, bridge submissions, staking writes, Lightning sends, and strategy activation when the required barrier is unavailable.

## 6. Availability and recovery

### Failure handling

- **One replica down:** quorum remains available; health is degraded and the event is audited.
- **Quorum unavailable:** no new report is acknowledged as committed, and wallet-core final barriers fail closed.
- **Leader loss:** a new leader must prove a committed log prefix before serving writes.
- **Replica divergence:** the divergent replica is fenced, re-seeded from a signed checkpoint, and cannot serve wallet-core barriers until caught up.
- **Checkpoint key compromise:** rotate the registry signing key through a quorum-committed key-rotation command, publish a new trust bundle, and invalidate old checkpoint keys after a grace period.
- **Storage corruption:** restore from the latest verified checkpoint plus the committed log suffix; compare the rebuilt state root before rejoining.
- **Evidence-store outage:** reports may be accepted only if the evidence hash and metadata are durably recorded; missing blobs never clear active quarantine.

### Disaster recovery targets

Initial targets should be explicit and tested rather than assumed:

- RPO: zero committed quarantine commands after quorum acknowledgement;
- RTO: defined by the product release tier, with final writes blocked until registry quorum and trust bundles recover;
- restore verification: state root, log head hash, checkpoint signature, and command sequence must match;
- quarterly restore drill with a synthetic compromised replica and stale-checkpoint scenario.

## 7. Operational controls

- Registry nodes run in separate failure domains with mutually authenticated service identities.
- HSM-backed registry signing keys are separate from wallet signing keys and hardware authorization keys.
- Operators cannot reverse quarantine through database access; reversal is a signed command through the user authorization protocol.
- Every read barrier emits `registry_version`, `state_root`, node quorum, freshness, and decision outcome to the audit stream.
- Metrics include commit latency, replica lag, checkpoint age, read-barrier failures, stale-ticket rejections, quarantine propagation latency, and reversal attempts.
- Alerts fire on version gaps, conflicting checkpoints, unexpected reversal rates, replica divergence, clock skew, and repeated failed hardware assertions.
- The service uses strict clock bounds for freshness, but correctness never depends on a single wall clock: version and quorum certification remain authoritative.

## 8. Migration plan from the in-memory reference

1. Keep the current `QuarantineRegistry` trait as the wallet-core contract.
2. Add a `CertifiedSnapshot` and `ReadBarrier` result type without changing the `IntentFootprint` or guard semantics.
3. Implement a single-node durable adapter for deterministic replay and crash recovery tests.
4. Add the 3-node quorum service and signed checkpoint verification.
5. Run old and new registries in shadow mode; compare versions, active entities, and state roots.
6. Require a matching certified head before enabling production signing.
7. Cut over report writes first, then wallet-core barriers, then subscription-driven cache invalidation.
8. Keep the in-memory implementation only for unit tests; mark it `#[cfg(test)]` or move it to a test support crate.
9. Delete any Python production path that can sign, broadcast, or bypass the Rust guard.

## 9. Release gates

The replacement is not production-ready until tests prove:

- crash recovery never loses a quorum-acknowledged command;
- two leaders cannot produce accepted conflicting checkpoints;
- stale signed checkpoints are rejected at sign and broadcast;
- a committed quarantine propagates to every healthy linked-wallet replica;
- a lagging or partitioned replica fails closed;
- duplicate reports and duplicate reversals are idempotent;
- user-only reversal is cryptographically verified and cannot be forged by an agent;
- registry key rotation and checkpoint trust-bundle rotation are recoverable;
- state-root replay from genesis/checkpoint produces the same active index;
- all existing 21 reference tests continue to pass against the durable adapter;
- race tests run with faults injected between simulation, signing, and broadcast.

## Final recommendation

Adopt the quorum log, signed checkpoint, and read-barrier design as the production target. Do not expose the current `InMemoryQuarantineRegistry` beyond tests, and do not treat a signed but stale snapshot as sufficient authorization for a value-moving operation.

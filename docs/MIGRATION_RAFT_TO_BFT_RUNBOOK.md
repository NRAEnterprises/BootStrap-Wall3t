# BootStrap Wall3t — Quarantine Registry Migration Runbook

**Status:** implementation runbook for production change review  
**Scope:** migration from the 3-node trusted-operator Raft crash-fault tier to the 7-node Byzantine-fault-tolerant quorum tier  
**Target:** 7 voting members, 5-of-7 commit certificates, `f = 2` under the selected BFT protocol  
**Non-goal:** adding two voters to a Raft cluster does not create BFT. The target protocol and certificate verifier must be deployed and tested before the guarantee changes.

## 1. Change statement and safety invariant

The migration changes the quarantine registry's replication and certificate model while preserving the wallet-core contract: monotonic registry versions, signed checkpoints, current read barriers at sign and broadcast, deny-before-write, user-only reversal, and fail-closed behavior.

The cutover is successful only if every accepted checkpoint has one unambiguous history and a verifiable 5-of-7 certificate. A stale, Raft-only, unsigned, under-quorum, or conflicting checkpoint must be rejected by wallet-core. During any uncertainty, affected value-moving operations stop; read-only views may continue with an explicit stale/degraded indicator.

The topology transition is deliberately phased:

```text
3 Raft voters (2/3) -> 5 transitional voters (3/5) -> 7 BFT voters (5/7)
```

The intermediate 5-voter stage is a controlled data-seeding and compatibility stage. It is not a claim of Byzantine tolerance unless the selected BFT protocol already has a formally verified 5-node configuration and the threat model accepts `f = 1`. The production target remains 7 BFT voters.

## 2. Preconditions and release blockers

Do not start the migration until all of the following are evidenced:

1. The durable state machine replays genesis and verified snapshots to the same active index, registry version, log-head hash, and Merkle state root.
2. The registry API has idempotent `command_id` handling for publish, reversal, membership, trust-bundle, and key-rotation commands.
3. Wallet-core accepts `CertifiedSnapshot`/read-barrier responses independently of whether the backend is Raft or BFT.
4. Final sign and broadcast gates reject stale snapshots, version gaps, invalid certificates, unknown trust keys, and quorum-unavailable reads.
5. The 20 reversal protocol vectors pass through the real authorization-service and registry state-machine harness; the simulator alone is not sufficient.
6. The 8 WebAuthn acceptance checks in `docs/WEBAUTHN_ACCEPTANCE_CHECKS.md` have no unresolved critical fail.
7. The BFT implementation has deterministic view-change, commit-certificate, membership, replay, equivocation, and conflicting-checkpoint tests.
8. Seven failure domains, node identities, mTLS credentials, HSM/threshold-key custody, backups, metrics, alerting, and on-call ownership are ready.
9. A signed checkpoint and trust-bundle backup has been restored successfully in an isolated environment.
10. Rollback is tested as a protocol transition, not as a database restore that can silently rewind registry versions.
11. A change window, incident commander, registry operator, wallet-core operator, security reviewer, and communications owner are assigned.

Any missing precondition is an abort condition. Do not compensate by reducing the read-barrier strictness.

## 3. Compatibility matrix

| Artifact | 3-node Raft | Transitional 5-node stage | 7-node BFT target | Compatibility rule |
|---|---|---|---|---|
| Registry version | committed log index | monotonic committed index | monotonic committed index | Never reset or reuse a version |
| State materializer | deterministic active index | same state-machine bytes | same state-machine bytes | Replay must produce identical root |
| Checkpoint | Raft-backed signed checkpoint | dual-labelled checkpoint during overlap | BFT certificate, 5-of-7 | Wallet-core accepts only configured valid certificate types |
| Trust bundle | Raft registry/checkpoint keys | old + new bundle during overlap | BFT membership + checkpoint keys | Unknown keys fail closed |
| Read barrier | quorum/committed-head proof | accepted from either certified path during overlap | BFT quorum proof | Freshness and version rules do not relax |
| Publish report | 2-of-3 commit | designated writer with mirrored BFT append | 5-of-7 BFT commit | One canonical command id and bytes |
| User reversal | expected Raft head | expected canonical head, dual receipt | expected BFT head | Head change invalidates challenge |
| Subscription | Raft checkpoint stream | deduplicated merged stream | BFT checkpoint stream | Apply only monotonic valid checkpoints |
| Cache invalidation | version advance | exactly once per committed version | exactly once per committed version | Lag never authorizes a write |
| Rollback | stop/freeze, no version rewind | stop/freeze, restore from certified prefix | stop/freeze, restore from certified prefix | Rollback means protocol mode, not state rewind |

## 4. Control-plane preparation

### 4.1 Freeze the semantic contract

Record the current Raft cluster id, membership, last committed version, log-head hash, state root, last checkpoint hash, active quarantine count, and trust-bundle version. Export the command log and evidence references by content hash. Confirm that no active report or reversal is being acknowledged outside the registry state machine.

Freeze schema changes, canonicalization changes, reason-code changes, and operation-footprint changes for the migration window. If a product change is required, abort the migration and restart from a newly reviewed checkpoint.

### 4.2 Prepare the BFT cluster

Provision seven voters in independent failure domains. Assign distinct node identities, mTLS certificates, storage, monitoring, and operator access. Generate or import the BFT membership/trust material under the approved HSM or threshold-key procedure. Record membership epoch and key fingerprints in the change ticket.

The BFT cluster starts in **non-serving observer mode**. It accepts seeded state and validates commands but cannot answer wallet-core barriers or commit production writes until promotion.

### 4.3 Data re-seeding

1. Quiesce snapshot compaction on the Raft tier.
2. Create a signed export at a committed version `V_seed` containing the checkpoint, log-head hash, state root, active index, and the command suffix needed for replay.
3. Transfer the export over an authenticated channel; verify content hashes before import.
4. Load all seven BFT nodes from the same certified export.
5. Replay the suffix deterministically and compare version, head hash, active-record hashes, evidence references, and Merkle root on every node.
6. Run a synthetic publish and reversal in an isolated namespace. Verify idempotency and user-only reversal without exposing the result to production wallets.
7. Keep the Raft source read-only during the comparison window. Do not allow two independent writers.

A node with a different root or command sequence is fenced and re-seeded. It is not allowed to "catch up" by accepting a local database as truth.

## 5. Phased cutover

### Phase 0 — Observe and compare

Run Raft and BFT in shadow mode from the same canonical command stream. For every checkpoint compare registry version, previous-checkpoint hash, log-head hash, state root, active entity set, and command result. Alert on any mismatch, lag, duplicate, missing event, or non-deterministic materialization.

Exit when the comparison window covers normal report volume, a reversal, a duplicate delivery, a node restart, a replica re-seed, and a simulated stale checkpoint. Zero unexplained mismatches are required.

### Phase 1 — Expand 3 to 5 voters

Add two nodes to the transitional cluster and validate storage, identity, health, and replay. The service remains explicitly labelled `RAFT_CRASH_FAULT` unless the BFT protocol is already active and independently accepted.

The transitional quorum is 3-of-5 for the selected commit path. Do not silently switch a 2-of-3 assumption in wallet-core; the core sees a certified snapshot and a membership epoch, not a hard-coded node count.

Verify:

- a 3-node majority can commit only when the transitional protocol says it can;
- a 2-node partition cannot commit;
- the old 3-node members do not create a second accepted history;
- checkpoint hashes and versions remain continuous;
- cache invalidation occurs once for each new version.

### Phase 2 — Enable dual-certificate overlap

For a bounded overlap, the registry emits a new checkpoint format containing the canonical checkpoint fields plus either:

- the old Raft certificate and the new BFT certificate over the same checkpoint hash; or
- a signed transition certificate that binds the last accepted Raft checkpoint to the first accepted BFT checkpoint.

Wallet-core must verify both the old trust path and the new path during the overlap, but must never accept two different state roots at the same version. The overlap has an explicit expiry version/time. It is not a permanent compatibility mode.

Report writes may be mirrored for comparison, but there is still one authoritative command id and one committed outcome. A report acknowledged by both paths is one logical command, not two registry versions.

### Phase 3 — Expand 5 to 7 voters and activate BFT

Join the final two voters as non-serving members, seed them from the latest certified transitional checkpoint, and verify the same root and log suffix. Advance the membership epoch through the BFT membership-change protocol.

Enable BFT commit certificates requiring 5-of-7 votes. Run a controlled canary report and confirm:

- the certificate contains five distinct eligible voter signatures or the protocol-equivalent proof;
- a certificate with four votes is rejected;
- conflicting certificates cannot both verify;
- an equivocal or malformed voter message is evidence and not a commit;
- a 4-node partition makes no progress;
- an honest 5-node side can progress only under the protocol's valid view-change rules;
- old Raft-only write paths are fenced.

### Phase 4 — Cut wallet-core barriers to BFT

Change the trust configuration so production wallet-core barriers require the BFT membership epoch and 5-of-7 certificate. Keep the old trust material only for bounded overlap verification and audit replay. At this point, stale or Raft-only snapshots must fail closed.

Switch in this order:

1. BFT checkpoint verification in read-only shadow mode.
2. BFT barrier verification for dashboards and simulation admission.
3. BFT barrier verification at signing.
4. BFT barrier verification at broadcast.
5. BFT-backed report writes.
6. Subscription-driven cache invalidation from the BFT stream.

Pause between each step long enough to observe metrics and synthetic transactions. Never enable broadcast before sign and broadcast barrier tests pass.

### Phase 5 — Declare BFT production

The incident commander records the cutover version, membership epoch, certificate policy, trust-bundle fingerprint, and all passing evidence. Announce the guarantee precisely: seven BFT voters, up to two Byzantine voters under the selected protocol and independent-failure-domain assumptions. Do not claim protection against compromised user hardware, compromised wallet signers, compromised majority control, or a faulty protocol implementation.

## 6. Quorum-size and trust-bundle transitions

Every checkpoint and barrier response includes `cluster_id`, `membership_epoch`, `registry_version`, `state_root`, `log_head_hash`, `certificate_type`, and `trust_bundle_version`. A response from an older epoch is accepted only if it is a valid predecessor certificate covered by the explicit overlap rule.

Rotate trust material in this order:

1. Publish the new BFT trust bundle and membership fingerprints through the existing trusted configuration channel.
2. Verify the bundle against an out-of-band release fingerprint.
3. Distribute it to all wallet-core barrier verifiers in shadow mode.
4. Observe dual verification of the transition certificate.
5. Activate the new bundle at a committed membership-change version.
6. Retain the old bundle for audit verification and bounded overlap only.
7. Revoke the old bundle after the overlap expiry and verify old-only checkpoints are rejected.

Checkpoint signing keys, BFT voter keys, WebAuthn admin credentials, wallet signer keys, and mTLS node identities remain separate trust domains. Rotation of one never substitutes for another.

## 7. Abort, rollback, and recovery criteria

Abort before cutover if any root/hash mismatch, missing command, duplicate version, clock-bound violation, certificate-verification disagreement, unexplained replica lag, evidence mismatch, or operator-access anomaly appears.

Abort after partial activation if any wallet-core verifier accepts an invalid or stale certificate, if a 5-of-7 certificate cannot be produced within the declared availability SLO, if a Raft-only path can still acknowledge a production write, if cache invalidation misses a committed version, or if any old positive ticket remains executable after a registry advance.

Rollback is a **freeze and protocol-mode rollback**, never a registry-version rewind:

1. stop report and reversal acknowledgements on the affected path;
2. disable final signing and broadcast barriers if the current certified head cannot be proven;
3. preserve all received commands, certificates, and evidence hashes;
4. fence divergent or suspected Byzantine nodes;
5. use the last mutually verified checkpoint and committed suffix to restore a clean cluster;
6. if policy permits returning to Raft during the overlap, require the exact dual-certificate transition proof and keep the registry version monotonic;
7. otherwise remain frozen until the BFT quorum is recovered;
8. invalidate all tickets from the uncertain epoch and re-run the read-barrier tests.

The rollback decision, reason, operator identities, last safe version, and restored root are immutable audit records.

## 8. Verification commands and evidence

The exact commands depend on the selected Rust registry service, but the release ticket must contain equivalent commands and captured output:

```bash
# Reference wallet-core regression
export PATH="$HOME/.cargo/bin:$PATH"
cargo test --all-targets --manifest-path rust/wallet-core/Cargo.toml
cargo clippy --all-targets --manifest-path rust/wallet-core/Cargo.toml -- -D warnings

# Elixir management-plane regression
cd elixir/wall3t_orchestrator
mix test

# Reversal protocol state vectors
cd ../..
python3 tools/simulate_reversal_protocol.py

# Required registry-service checks (service-specific CLI)
registryctl cluster status --membership-epoch <E>
registryctl checkpoint verify --version <V> --trust-bundle <BUNDLE>
registryctl state-root replay --checkpoint <CHECKPOINT> --log <LOG_EXPORT>
registryctl quorum test --required 5 --members 7
registryctl fault inject --scenario stale-checkpoint
registryctl fault inject --scenario equivocation
registryctl fault inject --scenario quorum-loss
```

Evidence includes command output, checkpoint files, trust-bundle fingerprints, membership-change receipts, replay roots, fault-injection results, cache-invalidation metrics, and the signed change record.

## 9. On-call checklists

### Before the window

- Confirm incident commander and rollback authority.
- Confirm backups, restore drill, and out-of-band trust fingerprints.
- Confirm no pending schema, key, or canonicalization changes.
- Confirm current version/root/head and active quarantine count.
- Confirm alerting for certificate failures, lag, version gaps, and stale barriers.
- Confirm wallet-core can be switched to fail-closed mode.

### During the window

- Record each phase start/end and observed version.
- Watch certificate verification failures and quorum latency.
- Compare roots at every phase boundary.
- Run only synthetic canary writes until the phase exit is signed.
- Check that one committed quarantine invalidates all positive caches.
- Check that old tickets fail at sign and broadcast.
- Check that Raft-only endpoints return fenced/unsupported, not success.

### After the window

- Verify 7/7 membership health and 5-of-7 commit behavior.
- Verify old trust material is in overlap-only state.
- Verify a four-vote certificate is rejected.
- Verify a stale Raft checkpoint is rejected.
- Verify user-only reversal still requires the actual WebAuthn acceptance gates.
- Archive all logs, roots, certificates, metrics, and approvals.
- Publish a post-change review with residual risks and next drill date.

## 10. Decommissioning Raft-only paths

After the overlap expiry and a successful restore/fault-injection review:

1. disable Raft-only report, reversal, checkpoint, and barrier endpoints;
2. remove old membership credentials from serving configuration;
3. reject old certificate types in wallet-core production configuration;
4. retain immutable Raft logs and checkpoints for audit/replay, not authorization;
5. remove dual-write code and transitional feature flags;
6. delete Raft-only production deployment manifests and credentials after retention approval;
7. update incident runbooks, metrics, threat model, and product claims;
8. repeat the full wallet-core race suite and BFT fault suite in CI;
9. record the decommissioned version and final trust-bundle fingerprint in `docs/BUILD_PLAN.md`.

The migration is complete only when no production code path can mistake a 3-node crash-fault certificate for a 7-node BFT certificate, and when the wallet-core trust boundary remains fail-closed throughout the change.

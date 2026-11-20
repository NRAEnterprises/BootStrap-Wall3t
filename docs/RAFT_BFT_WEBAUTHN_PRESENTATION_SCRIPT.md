# BootStrap Wall3t — Raft-to-BFT Migration & WebAuthn Reversal Presentation Script

**Audience:** registry operators, security reviewers, wallet-core maintainers, and incident responders  
**Purpose:** explain the migration from the 3-node Raft crash-fault tier to the 7-node BFT target and the hardware-authorized reversal protocol that protects the global quarantine state.  
**Status:** design and release-gate narrative; it does not claim that the production registry or WebAuthn verifier is implemented.

## Slide 1 — Why the registry change matters

The quarantine registry is a security coordination primitive, not an ordinary market-data database. If a bad token, contract, provider, or strategy family is committed, every linked wallet must stop relying on a stale positive decision.

The current three-node Raft tier is useful for a trusted operator and crash faults. It is not Byzantine tolerant. The migration changes the fault model while preserving the wallet-core promise: monotonic versions, deny-before-write, fresh read barriers, and fail-closed behavior.

Today’s narrative covers two controls. First, how the registry expands to seven BFT voters. Second, how only the user can reverse an active quarantine with hardware-backed authorization.

**Transition:** Start with the guarantees, because node count alone does not create Byzantine safety.

## Slide 2 — The guarantee boundary

A three-node Raft cluster commits with two of three votes and tolerates one crashed or unreachable node under a trusted-operator assumption. One malicious voter can equivocate; the topology does not provide a Byzantine quorum proof.

A seven-node BFT cluster targets two Byzantine faults under the standard `N ≥ 3f + 1` bound. A commit certificate requires five of seven votes. Two conflicting certificates must overlap in enough members that at least one honest voter would have to violate the protocol.

That guarantee is conditional. Seven Raft nodes are still Raft, not BFT. The implementation, voter independence, key custody, membership changes, and read-barrier verifier must all match the claim.

**Transition:** We therefore migrate in controlled phases rather than changing a configuration number.

## Slide 3 — 3 → 5 → 7 migration shape

The migration has three topology stages: three Raft voters, five transitional voters, and seven BFT voters. The five-voter stage is a data-seeding and compatibility stage unless a formally accepted five-node BFT profile is active.

At every stage, the registry version remains monotonic. The state machine, command bytes, log-head hash, active deny index, and Merkle root must replay identically. A node that diverges is fenced and re-seeded from a certified checkpoint.

The intermediate stage gives operators room to compare old and new materialization without giving the new cluster two independent writers.

**Transition:** Before any wallet sees the new certificate, the control plane needs a verified common history.

## Slide 4 — Shadow comparison and data re-seeding

The BFT cluster starts as a non-serving observer. Operators export a signed Raft checkpoint at a committed version, including the log head, state root, active records, and replay suffix.

All seven target voters load that same certified export. Each node replays the suffix and compares version, command sequence, active record hashes, evidence references, and Merkle root. The cluster is tested with duplicate reports, reversal attempts, node restart, and stale checkpoints before it serves a wallet barrier.

The safety rule is simple: no local database becomes truth merely because it is newer on disk. Only a certified history can seed the target cluster.

**Transition:** Once the histories match, the old and new trust paths overlap for a bounded window.

## Slide 5 — Dual certificates and trust-bundle rotation

During overlap, the registry binds the last accepted Raft checkpoint to the first accepted BFT checkpoint. Wallet-core can verify both paths, but it cannot accept two roots at the same version. The overlap has an explicit expiry; it is not a permanent compatibility mode.

The new BFT membership and checkpoint trust bundle is distributed in shadow mode, verified against an out-of-band fingerprint, and activated at a committed membership epoch. The old bundle remains available only for bounded audit and transition verification.

Checkpoint keys, voter keys, WebAuthn administrator credentials, wallet signer keys, and mTLS identities are separate trust domains. Rotating one must never substitute for another.

**Transition:** With the trust path ready, the cluster can activate the five-of-seven commit rule.

## Slide 6 — BFT cutover and abort criteria

The seven-voter target requires a valid five-of-seven certificate. Four votes are insufficient. A four-node partition must stop progress. A five-node side can proceed only if the BFT protocol’s view-change rules validate the committed prefix.

Wallet-core barriers switch in order: shadow verification, read-only and simulation admission, signing, broadcast, report writes, and finally subscription-driven cache invalidation. Each phase pauses for metrics and synthetic canaries.

Abort on conflicting roots, certificate disagreement, version gaps, unexpected lag, invalid freshness, Raft-only writes, missed cache invalidation, or old tickets that remain executable after a registry advance. Rollback means freeze and recover from a certified prefix; it never rewinds registry versions.

**Transition:** The registry protects the deny state, but a deny state also needs a disciplined way to be reversed.

## Slide 7 — Reversal is not a transaction approval

A quarantine reversal changes one control-plane record from `ACTIVE` to `REVERSED`. It does not approve a trade, unlock an agent, or restore old execution tickets. The reversal creates a new registry version and invalidates older positive decisions.

The user reviews the active record, evidence hashes, affected scope, current version, and state root. The authorization service then creates a one-time, short-lived challenge bound to that exact review.

The user’s hardware credential proves control of the administrative principal. Agents, database operators, and wallet transaction signatures cannot satisfy this protocol.

**Transition:** The challenge binds what the user saw to what the registry will commit.

## Slide 8 — WebAuthn assertion and server verification

The challenge includes protocol domain, authorization id, user, registry, quarantine id, active-record hash, expected version, expected state root, evidence-review hash, action, and expiry. The hardware assertion is requested with the dedicated RP id and required user verification.

The server verifies the complete WebAuthn envelope: type, challenge, origin, RP hash, UP and UV flags, credential ownership, algorithm, signature, and counter behavior. It does not trust the extension to verify its own assertion.

Canonical encoding prevents field-order and type ambiguity. The authorization digest is domain-separated and is recomputed before any command is submitted.

**Transition:** Hardware proof is necessary, but the registry still has to validate the expected head atomically.

## Slide 9 — Atomic commit and replay defenses

The registry leader checks that the authorization id is unused, the challenge is fresh, the expected version is current, the record is active, the user owns the credential, and the command bytes match the authorization transcript.

Only then does the quorum append `ACTIVE(version N) → REVERSED(version N+1)`. The registry emits a new signed checkpoint and linked wallets invalidate old tickets and positive caches.

Replay, rollback, phishing, counter rollback, wrong-origin, wrong-RP, changed evidence, key rotation, and stale-checkpoint paths all fail closed. Duplicate delivery is idempotent only when the command id and canonical bytes are identical.

**Transition:** The final question is what evidence allows production acceptance.

## Slide 10 — Acceptance gates and operating posture

The deterministic simulator passes 20 of 20 protocol-state vectors, but it does not implement real WebAuthn, canonical CBOR, ES256 verification, quorum certificates, or the end-to-end service path. Those remain explicit gates.

Production acceptance requires real envelope parsing, binding and signature verification, counter policy, credential ownership, audited cryptography, canonical transcript verification, checkpoint and quorum verification, and the complete authorization-to-wallet-core path.

The operational posture is deliberately conservative: read-only views may degrade, but affected signing and broadcast stop when state is stale, unavailable, unverifiable, or below quorum. The migration is complete only when a Raft-only path cannot authorize a production write and a hardware assertion cannot bypass the registry’s expected-head checks.

**Closing line:** Seven BFT voters protect the registry’s history; one verified hardware reversal protects the user’s right to correct an active deny decision without weakening autonomous execution or custody boundaries.

## Reviewer questions to pre-empt

**Does moving to seven nodes automatically create BFT?** No. The selected protocol and certificate verifier must provide the BFT guarantee.

**Can the migration rewind the registry if rollback is needed?** No. Rollback freezes writes and restores from a certified prefix without reusing versions.

**Can an agent reverse a bad-token quarantine?** No. Only the user’s verified hardware authorization can produce the reversal command.

**Does a signed checkpoint prove freshness?** No. Wallet-core still requires a current read barrier at sign and broadcast.

**Does the 20-vector simulation close the WebAuthn gate?** No. It validates protocol-state outcomes; real audited WebAuthn/CBOR/ES256 execution remains required.

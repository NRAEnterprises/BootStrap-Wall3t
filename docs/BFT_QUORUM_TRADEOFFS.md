# Quarantine Registry Quorum — 3-Node vs 7-Node BFT Trade-Offs

**Review date:** 2026-11-20
**Scope:** production quarantine registry commit and read-barrier topology
**Decision:** use 3 nodes only for trusted-operator crash-fault development; use 7 nodes when the registry must tolerate Byzantine behavior from up to two voting members

## Executive conclusion

A 3-node deployment is a good **crash-fault-tolerant Raft** configuration: it tolerates one crashed or unreachable node and commits with two votes. It is **not** a meaningful Byzantine-fault-tolerant configuration. Under the standard `N >= 3f + 1` bound, three nodes support `f = 0`; one malicious node can equivocate or sign conflicting views without the topology having the quorum intersection needed to prove safety.

A 7-node deployment supports **Byzantine fault tolerance for `f = 2`** under a PBFT/HotStuff/Tendermint-style protocol: it requires five votes for a commit, any two nodes may be malicious, and honest quorum certificates retain an honest intersection. It costs more in quorum latency, cross-region traffic, key management, operations, and degraded-mode complexity.

The registry is a security coordination primitive. A false positive quarantine is disruptive, but a false negative after a committed report can authorize value movement. If registry nodes are controlled by one trusted operator and the threat model is crash faults, three-node Raft is reasonable for the first production tier. If operators, regions, cloud accounts, or HSM control are intentionally independent, seven-node BFT is the safer target.

## 1. Fault model comparison

| Topology | Protocol assumption | Faults tolerated | Commit quorum | What it does not tolerate |
|---|---|---:|---:|---|
| 3 nodes | Raft / crash fault | 1 crash or partitioned node | 2 of 3 | 1 Byzantine node; equivocation; conflicting signed views |
| 3 nodes | Classical BFT | 0 Byzantine nodes (`3f+1`, f=0) | Not useful as BFT | Any malicious voter |
| 4 nodes | Classical BFT | 1 Byzantine node | 3 of 4 | 2 Byzantine nodes |
| 7 nodes | Classical BFT | 2 Byzantine nodes (`3f+1`, f=2) | 5 of 7 | 3 Byzantine nodes |
| 7 nodes | Raft / crash fault | 3 crash or partitioned nodes | 4 of 7 | 1 malicious node can still violate a trusted-state assumption |

For the requested comparison, seven nodes only earns its BFT benefit if the implementation is actually a BFT protocol or an equivalent threshold-signature protocol. Running Raft on seven nodes improves crash tolerance but does not make the system Byzantine tolerant.

## 2. Quorum mathematics

### Three-node crash-fault Raft

A majority is two votes. Any two healthy nodes can elect a leader and commit. One failed node leaves the system available. A network partition with a 2/1 split lets the majority side continue; a 1/2 split leaves the minority unable to commit.

The safety assumption is that voting members follow the protocol and their keys are not maliciously used. If one member equivocates, the system relies on the remaining protocol implementation, operator isolation, and key controls rather than a Byzantine quorum proof.

### Seven-node BFT

For `N = 7`, the standard bound gives `f = floor((N-1)/3) = 2`. A commit certificate requires at least `2f+1 = 5` votes. Two conflicting certificates of size five must overlap in at least three nodes; at least one of those overlap members is honest if only two are Byzantine. That honest intersection cannot sign conflicting committed histories under the protocol rules.

A four-node partition cannot make progress because it cannot reach five votes, but that is the correct safety-over-availability result. An isolated five-node side can progress only if it still contains enough honest members and the protocol's view-change rules validate the committed prefix.

## 3. Operational trade-offs

### Availability and partitions

Three-node Raft is easier to keep available in a small deployment: two reachable nodes are sufficient. Seven-node BFT needs five reachable voters. This makes a poorly placed seven-node cluster more fragile than a well-placed three-node cluster.

Placement matters more than raw node count. Seven nodes should span at least five independent failure domains, separate cloud accounts or operators where possible, and independent HSM/control-plane credentials. A seven-node cluster in one availability zone is not meaningfully resilient.

### Latency and throughput

Three-node Raft normally needs one leader round trip to a majority. Seven-node BFT needs a commit path with five votes and often multiple protocol phases, plus view-change traffic during leader faults. The registry write rate is expected to be low relative to chain activity, so this latency is usually acceptable for quarantine reports and reversals. It should not be inserted into every read-only dashboard request.

Wallet-core sign and broadcast gates do need a fresh barrier. To avoid making every read expensive, use local certified snapshots for admission and a quorum-backed freshness check at final write gates.

### Cost and operations

Seven nodes add storage, monitoring, patching, certificate rotation, HSM or threshold-key management, backup, disaster recovery, and incident coordination. The cost is justified only by a threat model that includes a malicious operator, compromised node, colluding storage administrators, or independent service providers.

Three nodes reduce operational load and are appropriate for a first vertical slice or a single trusted operator with strong host and HSM controls. They should be labeled crash-fault tolerant, not Byzantine tolerant.

### Trust and governance

The topology should match authority separation:

- 3-node Raft: one organization, separate regions, separate node credentials; operational simplicity.
- 7-node BFT: multiple independent operators, organizations, regions, or trust domains; stronger resistance to collusion by up to two voters.
- Hybrid: 7 BFT voters with a separate HSM-backed registry checkpoint key and a wallet-core trust bundle; the checkpoint signer must not be able to unilaterally commit state without the quorum protocol.

Node diversity is not automatically security. An independent operator with access to the same cloud account or trust bundle may not be truly independent.

## 4. Recommended deployment tiers

### Tier 0 — Development and deterministic tests

Use the existing in-memory registry and a single durable-node emulator. Exercise state-machine replay, idempotency, stale checkpoint handling, and wallet-core barriers. This tier makes no availability or Byzantine claim.

### Tier 1 — First production/testnet deployment

Use three Rust registry nodes with Raft, separate failure domains, mTLS node identities, HSM-backed checkpoint signing, and explicit crash-fault labeling. Require two-node commit and block final writes when quorum is unavailable.

This tier is appropriate while the project validates the EVM adapter and operational workflows, but it must not be described as BFT.

### Tier 2 — Production adversarial deployment

Use seven BFT voters with a 5-of-7 commit certificate, independent failure domains, operator diversity, signed checkpoints, state-root proofs, and a separate user-hardware authorization service. Require a fresh quorum read barrier for signing and broadcast.

Move to this tier when the registry is expected to withstand a compromised node or operator, when linked wallets span independent custody environments, or when legal/security review requires Byzantine-resilient coordination.

## 5. Failure scenarios

| Scenario | 3-node Raft | 7-node BFT |
|---|---|---|
| One node crashes | Commits with 2/3 | Commits with 6/7 or 5/7, depending on protocol |
| One region unavailable | Depends on placement; majority must remain | Depends on placement; five honest voters must remain reachable |
| One node equivocates | No Byzantine quorum guarantee | Safety preserved if no more than 2 Byzantine nodes |
| Two nodes collude | Safety depends on trusted-operator assumption | Safety preserved if only 2 are Byzantine; availability may degrade |
| Network partition | Majority side can commit | A side needs 5/7 and valid view-change proof |
| Stale replica serves wallet core | Must be rejected by read barrier | Must be rejected by checkpoint and freshness verification |
| Registry signing key compromised | Rotate trust bundle and freeze writes | Same, plus quorum membership and threshold controls |

## 6. Decision record

The production architecture should be protocol-pluggable but should not blur the guarantee:

```text
RegistrySafety = protocol guarantee + node independence + key custody + read barrier
```

Recommended implementation order:

1. Build the durable deterministic state machine and certified snapshot verifier.
2. Deploy three-node Raft for testnet/early production with explicit crash-fault scope.
3. Keep the wallet-core API independent of Raft versus BFT; it consumes certified snapshots and read barriers.
4. Implement a seven-node BFT adapter or threshold-certificate layer before claiming Byzantine tolerance.
5. Run fault injection for equivocation, conflicting checkpoints, stale views, leader replacement, and quorum loss.

## Final recommendation

Choose **3-node Raft** for the first operational vertical slice only if the project accepts a trusted-operator crash-fault model and labels it honestly. Choose **7-node BFT** for the target production registry if quarantine correctness must survive up to two malicious or compromised voting members. Do not call a 7-node Raft cluster BFT, and do not call a 3-node cluster BFT merely because it uses signatures.

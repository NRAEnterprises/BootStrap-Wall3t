# BootStrap Wall3t — Phase 2 Module 2.7 Presentation Script

## Slide 1 — Module 2.7: Production IPC Hardening

**On slide:**

- Bounded transport workers
- Fail-closed peer identity
- Split-account deployment draft
- Fault and recovery evidence

**Speaker script:**

Phase 2 Module 2.7 hardens the local boundary between the Elixir automation plane and Rust wallet-core. The goal is not to add a transaction approval queue or move authority into Elixir. The goal is to make the existing automation-first architecture resilient against slow clients, identity confusion, path substitution, process loss, and unsafe deployment defaults.

The result is a stronger transport boundary, while Rust remains authoritative for authentication, replay, policy, signing, and broadcast decisions.

## Slide 2 — Threat Model

**On slide:**

- Slow or malicious local clients
- Wrong UID or group
- Symlinked runtime paths
- Rust process termination
- Replay-state loss
- Secret-bearing diagnostics

**Speaker script:**

The relevant threat model is local and operational. A client may connect and send only a partial frame. A wrong local account may reach the socket. A parent directory may be substituted through a symlink. The Rust process may terminate during a request. A deployment mistake may expose the socket with the wrong owner or mode. Finally, a failure path must not leak authenticated payloads or key material into logs.

Module 2.7 treats each of these as a fail-closed deployment or transport condition.

## Slide 3 — Bounded Worker Architecture

**On slide:**

```text
Unix listener
     |
     v
try_send -> bounded queue(16)
     |
     +--> worker 1
     +--> worker 2
     +--> worker 3
     +--> worker 4
```

**Speaker script:**

The former sequential listener could be held by one client that sent an incomplete frame. The new endpoint uses four fixed workers and a bounded sixteen-connection queue. The accept loop uses nonblocking dispatch. If the queue is full, the connection is closed rather than making the listener wait indefinitely.

Every connection receives fixed five-second read and write deadlines. These limits are compiled into a typed transport configuration rather than accepted from an untrusted environment variable.

## Slide 4 — Request Ordering and Replay Safety

**On slide:**

1. Accept connection
2. Apply deadlines
3. Attest peer
4. Read frame
5. Decode BWAU
6. Verify signature and replay state

**Speaker script:**

The security ordering remains strict. Peer credentials are checked before any request frame is read. Only an authorized peer reaches BWAU decoding. Only a valid authenticated envelope reaches durable replay verification and nonce consumption.

A rejected peer cannot consume a nonce. A truncated frame cannot reach wallet policy. A timeout does not create a positive execution decision.

## Slide 5 — Split-Account Identity Attestation

**On slide:**

- `wall3t-core` owns Rust
- `wall3t-orchestrator` owns Elixir
- `wall3t-ipc` is the dedicated group
- Effective or supplementary group verified
- Unsupported attestation fails closed

**Speaker script:**

Production uses separate service identities. Rust runs as `wall3t-core`; Elixir runs as `wall3t-orchestrator`; `wall3t-ipc` is the only approved communication group.

The peer UID is verified through Unix peer credentials. If the effective GID differs from the configured IPC group, Linux supplementary-group membership is checked using the kernel-reported peer PID and procfs group metadata. If the platform cannot attest the required identity, production authorization fails closed.

The effective-group deployment remains preferred because it is easier to verify and less sensitive to process-group races.

## Slide 6 — Path and Filesystem Hardening

**On slide:**

- Root-provisioned runtime directory
- `/run/wall3t/wallet-core` mode `2750`
- Socket mode `0660`
- No symlinked path components
- No broad cleanup deletion
- Replay state outside socket directory

**Speaker script:**

The socket is no longer validated only through a metadata call that could follow a symlinked parent. Each parent component is checked with no-symlink metadata traversal before bind. Parent traversal, missing components, non-directory ancestors, and symlink components are rejected.

The host provisions the runtime directory with tmpfiles.d. Rust does not create or broaden the production runtime path. Replay state lives separately and is not placed next to the socket.

## Slide 7 — systemd and tmpfiles Deployment Draft

**On slide:**

```text
root:wall3t-ipc 0750 /run/wall3t
root:wall3t-ipc 2750 /run/wall3t/wallet-core
wall3t-core:wall3t-core 0700 /var/lib/wall3t/wallet-core
wall3t-core:wall3t-ipc 0660 wallet-core.sock
```

**Speaker script:**

The deployment artifacts define a root-owned runtime layout, separate replay state, service ordering, restricted address families, no-new-privileges, and systemd dependency coupling.

These are drafts rather than a production claim. Installation still requires real account IDs, approved binary paths, root-owned configuration, generated current-time handling, and a deliberate decision that systemd—not Elixir’s in-process supervisor—owns the Rust lifecycle.

## Slide 8 — Fault and Recovery Evidence

**On slide:**

- Partial header timeout: pass
- Partial payload timeout: pass
- Disconnect before/during frame: pass
- Queue saturation: pass
- Rust exit during request: pass
- Same-journal restart: pass
- Valid post-restart request: pass

**Speaker script:**

The process-level fault harness now covers the remaining Module 2.7 transport cases. Partial frames time out with bounded errors. Disconnects leave the service healthy. Worker saturation does not block the accept loop. Rust termination closes the incomplete request, and a restart using the same journal accepts a valid request without resetting replay state.

The harness also scans captured service output and rejects authenticated envelope or public-key material in logs.

## Slide 9 — Readiness and Health Boundary

**On slide:**

**Implemented now:**

- Metadata readiness probe
- Socket type, owner, group, mode
- Runtime directory mode

**Designed for next iteration:**

- Connection-bound `HREQ → HCHL → HACK → HOK`
- No BWAU decoding
- No replay consumption

**Speaker script:**

The current readiness probe is intentionally metadata-only. It checks socket type, ownership, group, mode, non-symlink status, and runtime-directory permissions.

A future health protocol is designed separately. It uses a connection-bound challenge exchange authenticated by the existing peer-credential boundary. It does not submit a normal BWAU envelope, does not consume a replay nonce, and does not expose wallet metadata. That protocol must be implemented and tested before the deployment can claim a non-consuming authenticated health exchange.

## Slide 10 — Results and Remaining Gates

**On slide:**

- 54 Rust unit tests passed
- 9 Rust integration tests passed
- Clippy and formatting clean
- Transport fault suite passed
- Authenticated socket E2E passed
- Restart/replay E2E passed

**Remaining:**

- Real split-account host installation
- Service-manager identity verification
- Health protocol implementation
- External security review

**Speaker script:**

Module 2.7 has local implementation and validation evidence. Fifty-four Rust unit tests, nine integration tests, formatting, Clippy, authenticated socket E2E, restart/replay recovery, timeout, disconnect, saturation, Rust-exit, path-substitution, readiness, and log-review cases all pass.

The remaining work is operational and security-critical: install the artifacts on a real split-account host, verify service-manager identity semantics, implement the non-consuming health exchange, complete platform-specific acceptance, and obtain external security review.

The central architectural result is unchanged: this remains an automation-first wallet. Policies and orchestration stay autonomous, while Rust retains the authoritative trust boundary and all fail-closed execution controls.

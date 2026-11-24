# BootStrap Wall3t — Non-Consuming IPC Health Protocol

**Status:** Future protocol design; not implemented by the current wallet-core socket.

## 1. Purpose

The current readiness probe verifies filesystem and socket metadata only. It must not submit a normal BWAU envelope because normal envelope admission consumes a durable replay nonce.

This design adds a small connection-bound health exchange that proves:

1. The client reached the expected Unix socket.
2. The Rust endpoint is alive and processing requests.
3. The peer passed the production UID/group authorization gate.
4. The endpoint’s replay and key-registry state are available.
5. The exchange itself does not enter the signing, broadcast, policy, or replay-consumption path.

The health protocol is a transport-control protocol, not a wallet operation.

## 2. Authentication model

The primary authentication factor is the existing Unix peer-credential boundary:

- Rust obtains `SO_PEERCRED` before reading any health request body.
- The peer UID must match the configured orchestrator identity.
- The effective or supplementary IPC group must match the configured `wall3t-ipc` group.
- Unsupported or unavailable attestation fails closed.

The exchange is connection-bound and challenge-based so a captured response cannot be replayed over a different connection. No wallet private key, mnemonic, signing key, BWAU nonce, or bearer token is used.

This design intentionally does not introduce a second Elixir signing authority. Elixir orchestrates and proves liveness through the already-authenticated local channel; Rust remains the authority for wallet authentication and execution.

## 3. Versioned wire format

Use a separate `BWH1` protocol domain so health frames cannot be confused with BWAU application envelopes.

All integers are unsigned big-endian. Every frame is bounded by the existing 4-byte frame length and a small health-specific maximum of 512 bytes.

### Client health request — `HREQ`

```text
magic              4 bytes  ASCII "HREQ"
version            u16      1
request_id         16 bytes random client request identifier
client_deadline    u64      monotonic-deadline representation or bounded lease
```

The client request contains no wallet identifier, strategy data, payload, signature, or replay nonce. `request_id` is for correlation only and must not be treated as a durable replay token.

### Rust challenge — `HCHL`

```text
magic              4 bytes  ASCII "HCHL"
version            u16      1
challenge          32 bytes cryptographically random connection challenge
server_instance   16 bytes opaque boot-instance identifier
expires_after_ms   u32      short challenge lifetime, recommended <= 2000
```

The challenge is held only in the connection worker’s memory. It is never persisted, logged, or included in an audit event.

### Client acknowledgement — `HACK`

```text
magic              4 bytes  ASCII "HACK"
version            u16      1
request_id         16 bytes exact HREQ request identifier
challenge          32 bytes exact HCHL challenge
```

The Rust worker accepts exactly one acknowledgement for the challenge and then discards it. A duplicate, mismatched, expired, or cross-connection acknowledgement is rejected.

### Rust health response — `HOK`

```text
magic              4 bytes  ASCII "HOK!"
version            u16      1
request_id         16 bytes exact request identifier
server_instance   16 bytes exact challenge instance identifier
state_flags        u32      non-secret readiness bitset
protocol_epoch     u64      monotonic protocol/configuration epoch
```

Recommended state flags:

| Flag | Meaning |
|---|---|
| `0x01` | Key registry loaded and internally available |
| `0x02` | Replay registry loaded and writable |
| `0x04` | Socket profile and peer policy active |
| `0x08` | Wallet-core policy authority available |
| `0x10` | Service is accepting authenticated application envelopes |

Only the exact expected bitset for the deployment may be considered ready. Unknown bits must fail closed.

### Bounded error — `HERR`

```text
magic              4 bytes  ASCII "HERR"
version            u16      1
request_id         16 bytes request identifier, if safely available
error_code         u16      numeric allowlisted error
```

Error responses contain no OS error strings, peer credentials, paths, payloads, signatures, or secret material.

## 4. Processing order

For every health connection:

1. Accept the Unix stream.
2. Apply read and write deadlines.
3. Obtain and verify peer credentials.
4. Read one bounded `HREQ` frame.
5. Validate the fixed magic, version, size, deadline, and request identifier.
6. Generate a fresh challenge using the operating system randomness source.
7. Store the challenge only in the worker-local connection state.
8. Write `HCHL`.
9. Read exactly one bounded `HACK` frame.
10. Compare request ID and challenge in constant-time where applicable.
11. Re-check that the connection remains within its deadline.
12. Inspect in-memory availability of key registry, replay registry, policy authority, and active profile.
13. Write `HOK` or a bounded `HERR`.
14. Close the connection.

The health path must not call:

- `AuthenticatedEnvelope::decode`.
- `PersistentNonceRegistry::verify_and_consume`.
- Signing, broadcast, policy execution, or wallet mutation APIs.
- Any operation that writes a durable replay record.

## 5. Failure behavior

The endpoint must return a bounded error or close the connection for:

- Unknown health magic.
- Unsupported version.
- Oversized health frame.
- Zero or malformed request ID.
- Expired client deadline.
- Challenge timeout.
- Mismatched request ID.
- Mismatched challenge.
- Duplicate acknowledgement.
- Peer UID/group failure.
- Registry or replay-state unavailability.
- Unknown state flags.

No health failure may cause a fallback to the development profile or make the application socket available.

## 6. Readiness integration

The preferred readiness sequence is:

1. systemd starts Rust.
2. `ExecStartPost` verifies filesystem/socket metadata.
3. The orchestrator readiness client performs `HREQ → HCHL → HACK → HOK`.
4. Elixir reports wallet-core ready only when the required `HOK` flags are present.
5. Normal BWAU application traffic remains a separate path.

The current `wallet-core-readiness` script should remain metadata-only until this protocol is implemented. It must not be modified to submit a fixture envelope as a health check.

## 7. Security and implementation constraints

- Use a separate protocol magic and domain from BWAU.
- Keep the maximum health frame below 512 bytes.
- Use OS randomness for the challenge; do not use timestamps as the challenge.
- Keep challenge state connection-local and discard it on success, failure, timeout, or disconnect.
- Never log the challenge, request ID, peer PID, or raw frame bytes by default.
- Return only numeric allowlisted errors.
- Do not expose registry paths, socket paths, key IDs, replay counts, or signer metadata in `HOK`.
- Make the protocol opt-in by explicit protocol version/profile configuration.
- Add a versioned test-vector file for valid, expired, mismatched, replayed, truncated, and oversized health frames.

## 8. Acceptance tests

Before enabling the protocol in production:

- [ ] A valid peer completes the two-round exchange.
- [ ] An unauthorized UID is rejected before `HREQ` decoding.
- [ ] An unauthorized group is rejected before `HREQ` decoding.
- [ ] The same `HACK` cannot succeed on a second connection.
- [ ] A challenge cannot be reused after a successful response.
- [ ] Expired challenges fail without durable state mutation.
- [ ] Health traffic does not change the replay journal byte-for-byte.
- [ ] Health traffic does not change registry versions or signing state.
- [ ] Partial health frames time out and do not block application workers.
- [ ] Rust exit and restart do not make a stale challenge valid.
- [ ] Response fields contain no secret or identifying wallet metadata.
- [ ] Unknown state flags and protocol versions fail closed.

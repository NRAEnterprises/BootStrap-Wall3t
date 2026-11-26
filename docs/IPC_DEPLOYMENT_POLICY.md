# BootStrap Wall3t — Deployment-Specific IPC Policy

**Status:** Design checkpoint 27
**Scope:** Elixir management plane to Rust wallet-core Unix-domain transport
**Classification:** Production security boundary

## 1. Security objective

The Unix socket is a local authenticated transport between the Elixir management plane and the Rust wallet core. Filesystem access is necessary but not sufficient for authorization. The deployment must restrict who can discover, connect to, replace, or impersonate the endpoint, and the Rust service must authenticate the connecting process before accepting a request.

No private key, seed, signing handle, credential, or unrestricted broadcast authority may cross this IPC boundary. Requests remain bounded authenticated BWAU envelopes and responses remain bounded public status metadata.

## 2. Approved production layout

| Resource | Required value |
|---|---|
| Runtime directory | `/run/wall3t/wallet-core` |
| Socket | `/run/wall3t/wallet-core/wallet-core.sock` |
| Rust service account | `wall3t-core` |
| Elixir service account | `wall3t-orchestrator` |
| IPC group | `wall3t-ipc` |
| Runtime directory owner/group | `root:wall3t-ipc` |
| Runtime directory mode | `2750` (`setgid`, owner full access, group traverse/read, no other access) |
| Socket owner | `wall3t-core` |
| Socket group | `wall3t-ipc` |
| Socket mode | `0660` |
| Parent filesystem | local runtime filesystem only; never NFS, shared storage, or a world-writable temporary directory |

The Rust service is launched with effective group `wall3t-ipc`; the Elixir service has `wall3t-ipc` as a supplementary or effective group. No other account, container, or service is a member of this group. Group membership changes require service restart and deployment approval. In socket-activation mode, systemd—not the Rust process—creates the socket node, so the runtime directory remains root-owned and non-writable by the IPC group.

The current reference endpoint forces `0600` and checks ownership against the effective process UID/GID. That is correct for same-identity development execution but does not support the approved split-account production layout. Production support therefore requires an explicit, reviewed IPC profile that changes the expected group and mode to the values above; it must not be implemented by weakening the default or accepting arbitrary environment-provided modes.

## 3. Runtime directory creation

The host service manager or an equivalent privileged provisioning step must create the directory before either service starts. The directory is provisioned with `wall3t-core` as owner because Rust must create the socket; the service manager, not the Rust or Elixir process, establishes that ownership and mode. Neither application process may create `/run/wall3t`, change its ownership, or broaden its permissions at runtime.

Required invariants:

- `/run/wall3t` and `/run/wall3t/wallet-core` are owned by `root:wall3t-ipc`.
- The wallet-core directory is `2750`; group write is prohibited.
- The directory is not a symlink, mount supplied by an untrusted service, or group/other-writable path.
- The socket path is absent before the Rust service binds.
- A stale socket is removed only after `lstat` confirms it is a socket and the service manager has confirmed the prior endpoint is stopped.
- A regular file, directory, or symlink at the socket path is never removed automatically.

A tmpfiles/systemd equivalent should provision the directory at boot and remove only the runtime directory contents at shutdown. The persistent replay journal must live separately under a restricted state directory, not beside the socket.

## 4. Peer authorization

Filesystem permissions protect the endpoint from ordinary local access; Rust must additionally inspect Unix peer credentials on every accepted connection before reading the request body:

1. Obtain `SO_PEERCRED` (or the platform-equivalent credential) from the accepted socket.
2. Require the peer UID to be `wall3t-orchestrator` or an explicitly enumerated deployment identity.
3. Require the peer process to belong to `wall3t-ipc` where the platform exposes supplementary groups, or use a narrowly scoped service-manager/cgroup identity assertion.
4. Reject unknown UID/GID credentials before BWAU decoding.
5. Record only non-secret peer identity metadata in the audit event.

The Rust public-key registry and BWAU signature remain authoritative application authentication. Peer credentials are a local channel authorization gate, not a replacement for envelope verification or replay protection. If peer-credential inspection is unavailable, the production profile must not start; the `0600` same-identity reference profile may remain available only for explicitly marked local development.

## 5. Service-manager contract

The host service manager must supervise Elixir as the top-level application and make Rust available only through the Elixir child lifecycle, or use an equivalent dependency relationship that has identical guarantees:

- Rust starts before Elixir declares the wallet-core transport ready.
- Elixir restarts Rust only under the bounded OTP restart policy.
- Repeated Rust failures stop the management plane rather than allowing workflows to continue without wallet-core.
- Stop ordering is Elixir, then Rust; socket cleanup occurs before a replacement bind.
- The replay journal is not deleted or replaced during restart.
- Service startup has a readiness check that verifies socket type, owner/group, mode, peer policy, and a non-secret authenticated health exchange.
- Service-manager logs must not contain BWAU payloads, signatures, credentials, or key material.

No `ExecStartPre` or cleanup hook may use a broad `rm -f` against the socket path. Cleanup must use type-aware `lstat` checks and a service identity/state check.

## 6. Forbidden configurations

The following are release-blocking violations:

- Socket mode `0666`, `0644`, `0620`, or any mode granting access to other users.
- Runtime directory mode with group/other write access, except a separately reviewed sticky-bit directory that is not approved for production.
- `/tmp` or another shared temporary directory as the production socket parent.
- Running Rust or Elixir as `root`.
- Sharing `wall3t-ipc` with web servers, shells, CI workers, agents, monitoring exporters, or unrelated services.
- Allowing a configurable socket mode, owner, group, or peer allowlist from an untrusted environment source.
- Following symlinks or replacing non-socket paths during cleanup.
- Treating filesystem access as sufficient authentication without BWAU verification and nonce consumption.
- Persisting the replay journal in an Elixir-writable or socket-directory path.
- Publishing the socket through TCP, abstract sockets without an equivalent policy, or a container port mapping.

## 7. Environment profiles

### Development reference profile

- Same controlled account for the Rust and Elixir processes.
- Private parent directory.
- Socket mode `0600`.
- No production peer-credential claim.
- Temporary replay journal allowed only for tests; fixtures must be public and secret-free.

### Production split-account profile

- Required directory, accounts, group, and `0660` socket policy from Section 2.
- Explicit Rust profile compiled/configured for expected group and mode.
- Mandatory peer credential attestation.
- Persistent replay journal under a separate root-owned state directory with atomic durable writes.
- Host service manager provisions runtime paths and applies no-broadening sandbox controls.

A deployment must identify its active profile in non-secret configuration and fail closed when a production profile is incomplete. It must never silently fall back from production to the development `0600` profile.

## 8. Acceptance tests

The production IPC implementation is not complete until tests prove:

- Directory ownership/mode and socket owner/group/mode match the selected profile.
- Group-authorized Elixir access succeeds; an unauthorized local UID is rejected.
- A forged BWAU from an authorized peer is rejected.
- A valid BWAU from an unauthorized peer is rejected before application processing.
- Symlink, regular-file, directory, and unsafe-parent substitutions fail closed.
- Rust restart permits a clean rebind without deleting non-socket paths.
- The replay journal survives restart and rejects the previously consumed nonce.
- Truncated/corrupt journal state prevents readiness and socket exposure.
- Timeout, disconnect, truncated request, and Rust-exit-during-request cases return bounded failures.
- No test artifact or service log contains private keys, credentials, or raw authenticated payloads.

## 9. Implementation order

1. Add a typed, non-arbitrary IPC profile with development and production variants.
2. Add Rust peer-credential attestation and fail-closed readiness.
3. Replace effective-GID-only socket assertions with explicit expected production group checks while retaining UID ownership checks.
4. Provision the runtime and persistent state directories through the host service manager.
5. Add split-account integration tests and negative permission/peer tests.
6. Run restart, replay-state, timeout, and disconnect fault injection before enabling production deployment.

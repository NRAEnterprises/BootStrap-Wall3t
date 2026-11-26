# BootStrap Wall3t — Production Release Checklist

**Status:** Release-gate template; not a production authorization
**Scope:** Rust wallet-core IPC endpoint, systemd socket activation, Elixir orchestrator, replay state, and deployment controls
**Owner:** Release engineering
**Required approvers:** Wallet-core owner, operations owner, independent security reviewer, administrator

This checklist must be completed on the target host with installation-specific values recorded. Passing the disposable sandbox staging harness is necessary evidence but does not substitute for target-host verification or independent approval.

## 1. Release identity and change control

- [ ] Record repository, branch, immutable commit, build timestamp, Rust toolchain, Elixir/OTP version, OS image, kernel, systemd version, and package inventory.
- [ ] Verify the target commit is the administrator-approved `main` commit and contains no uncommitted or generated artifacts.
- [ ] Produce a signed release manifest containing hashes for the Rust binary, Elixir release, systemd units, readiness probe, tmpfiles rule, environment-file template, and this checklist.
- [ ] Verify artifact provenance from a clean checkout and reproducible or independently reviewed build logs.
- [ ] Confirm release configuration contains public verification metadata only; no private keys, mnemonics, bearer tokens, RPC passwords, or signing handles.
- [ ] Open a maintenance window, identify the change ticket, name the operator, and identify the rollback commander and security approver.
- [ ] Confirm no live-chain transaction, broadcast, key rotation, or financial strategy activation is part of this deployment.

## 2. Target-host account and group identity record

Record numeric values; names alone are insufficient for peer-credential review.

| Identity | Required name | Numeric ID | Expected use | Verified by/date |
|---|---|---:|---|---|
| Rust service account | `wall3t-core` | `__________` | Owns wallet-core process and replay state | __________ |
| Elixir service account | `wall3t-orchestrator` | `__________` | Sole authorized application peer | __________ |
| IPC group | `wall3t-ipc` | `__________` | Socket access only | __________ |
| Release/operator account | `__________` | `__________` | Deployment only; never socket peer | __________ |

- [ ] `wall3t-core` and `wall3t-orchestrator` are non-root, non-login service identities with locked credentials and no interactive shell.
- [ ] `wall3t-ipc` contains only the approved orchestrator service account and, where required, the Rust effective group identity; no shell, CI, agent, web, monitoring, or unrelated member exists.
- [ ] Record `id wall3t-core`, `id wall3t-orchestrator`, and `getent group wall3t-ipc` output in the restricted deployment evidence store.
- [ ] Confirm the profile is exactly `production:<ORCHESTRATOR_UID>:<IPC_GID>` and is not sourced from an untrusted mutable runtime input.
- [ ] Confirm account/group changes require service restart and deployment approval.

## 3. Filesystem, ownership, and secret boundary

- [ ] `/run/wall3t` is a local filesystem directory owned by `root:wall3t-ipc`, mode `0750`, and is not a symlink.
- [ ] `/run/wall3t/wallet-core` is owned by `root:wall3t-ipc`, mode `2750`, setgid, and not group/other writable.
- [ ] `/run/wall3t/wallet-core/wallet-core.sock` is absent before socket activation and is created only by systemd.
- [ ] Socket is owned by `wall3t-core:wall3t-ipc`, mode `0660`; no other access is granted.
- [ ] `/var/lib/wall3t/wallet-core` is local, owned by `wall3t-core:wall3t-core`, mode `0700`, and separate from the socket directory.
- [ ] Every socket-parent component is checked with `lstat`/`symlink_metadata`; no symlink, traversal, mount substitution, or shared temporary path exists.
- [ ] `/etc/wall3t/wallet-core.env` is root-owned, mode `0640`, readable only by root and the approved wallet-core group, and contains public metadata plus numeric IDs only.
- [ ] Elixir environment configuration contains no private key material or unrestricted signer capability.
- [ ] Verify no tracked, packaged, unit, journal, crash-dump, or backup artifact contains credentials or raw authenticated payloads.

## 4. Service-manager and activation gate

- [ ] `systemd-analyze verify` passes on the rendered socket, wallet-core, and orchestrator units with installation-specific paths resolved.
- [ ] The socket unit has `ListenStream`, `SocketUser`, `SocketGroup`, `SocketMode=0660`, `Accept=no`, and `RemoveOnStop=yes` as approved.
- [ ] The wallet-core service consumes exactly one inherited FD 3 with matching `LISTEN_PID` and `LISTEN_FDS=1`; malformed or partial activation metadata fails closed.
- [ ] The wallet-core service runs as `wall3t-core:wall3t-ipc`, uses `NoNewPrivileges`, filesystem protection, `RestrictAddressFamilies=AF_UNIX`, and only the replay-state write path.
- [ ] The orchestrator runs as `wall3t-orchestrator:wall3t-ipc`, has external Rust lifecycle enabled, and cannot launch a second wallet-core endpoint.
- [ ] Start ordering is socket → wallet-core → authenticated health readiness → orchestrator.
- [ ] Stopping wallet-core blocks or stops the orchestrator; no workflow continues with an unavailable trust boundary.
- [ ] Restart policy, start-rate limits, stop timeouts, and dependency relationships are reviewed against the target host’s operational behavior.
- [ ] Readiness proves socket metadata and the non-consuming authenticated `HREQ → HCHL → HACK → HOK` exchange with flags `0x1f`.

## 5. Functional and negative acceptance gates

- [ ] Authorized orchestrator peer succeeds with a valid BWAU envelope.
- [ ] Wrong UID is rejected before frame/BWAU decoding.
- [ ] Wrong effective or supplementary group is rejected before application processing.
- [ ] Forged or invalid BWAU from an authorized peer is rejected.
- [ ] Replayed BWAU is rejected and the journal remains durable across restart.
- [ ] Corrupt, truncated, duplicate, zero-nonce, or over-capacity replay state prevents readiness and socket exposure.
- [ ] Partial header/payload, disconnect, Rust-exit-during-request, and queue-saturation tests pass with bounded failures.
- [ ] Regular-file, directory, symlink, traversal, and unsafe-parent substitutions fail closed without deleting the substituted path.
- [ ] Health traffic does not consume or mutate replay state; compare journal bytes before and after health checks.
- [ ] Logs and readiness output contain metadata only, never BWAU payloads, signatures, credentials, or key material.

## 6. Rollback readiness and drill evidence

- [ ] Previous approved binary, units, environment metadata, tmpfiles rule, and release manifest are retained in a versioned, access-controlled rollback location.
- [ ] Rollback commander and operator know the exact stop ordering: orchestrator, wallet-core, then socket if required.
- [ ] Replay journal is copied or snapshotted using a documented integrity-preserving method before change; it is never deleted or reset as part of rollback.
- [ ] A failed candidate start is demonstrated to leave the prior journal untouched and the socket unavailable or safely controlled.
- [ ] Previous units/binary are restored, `systemctl daemon-reload` is run, tmpfiles ownership is revalidated, and the socket is reactivated.
- [ ] Post-rollback health, authorized request, replay denial, identity, permissions, and log checks pass.
- [ ] Rollback drill records start/end time, commit IDs, artifact hashes, journal hash before/after, service states, and operator observations.
- [ ] Any journal mismatch, unexpected socket, identity drift, or readiness failure blocks release and triggers incident handling.

## 7. Independent security approval

The independent reviewer must not be the implementer or deployment operator.

- [ ] Review source diff, build manifest, unit rendering, environment injection, filesystem permissions, peer authorization, replay persistence, and rollback evidence.
- [ ] Review threat model for local UID/GID compromise, systemd activation spoofing, path substitution, service replacement, journal tampering, log leakage, and stale readiness.
- [ ] Confirm all open findings are either closed with evidence or explicitly accepted by the administrator with compensating controls and expiry date.
- [ ] Confirm no claim of production readiness relies solely on unit syntax checks or sandbox staging.
- [ ] Security reviewer records verdict: `APPROVED / CONDITIONALLY APPROVED / REJECTED`.
- [ ] Administrator records final release authorization separately from the security verdict.

## 8. Release decision

Release is permitted only when every mandatory checkbox is complete, numeric identities and hashes are recorded, rollback drill evidence is attached, and independent security approval is `APPROVED` or an administrator-approved conditional exception exists. Any failed identity, path, replay, readiness, secret-handling, or rollback check is a release blocker; do not broaden permissions or fall back to the development profile.

**Release verdict:** ____________________  **Date:** __________

**Wallet-core owner:** ____________________  **Operations owner:** ____________________

**Independent security reviewer:** ____________________  **Administrator:** ____________________

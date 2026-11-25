# BootStrap Wall3t — IPC Deployment Playbook

**Scope:** Phase 2 Module 2.7 split-account installation of the Rust wallet-core Unix socket and Elixir orchestrator.

**Status:** Draft for target-host review. This playbook does not authorize production installation until the account IDs, release paths, service-manager policy, and security review are approved.

## 1. Deployment contract

The approved production topology is:

| Resource | Required value |
|---|---|
| Rust service account | `wall3t-core` |
| Elixir service account | `wall3t-orchestrator` |
| IPC group | `wall3t-ipc` |
| Runtime directory | `/run/wall3t/wallet-core` |
| Runtime directory mode | `2750`, owner `root:wall3t-ipc` |
| Socket | `/run/wall3t/wallet-core/wallet-core.sock` |
| Socket mode | `0660`, owner `wall3t-core:wall3t-ipc` |
| Replay state | `/var/lib/wall3t/wallet-core/replay.bwnr` |
| Replay-state owner | `wall3t-core:wall3t-core` |

The Rust service is systemd-managed in this deployment mode. Elixir must not also start a second Rust child through `Wall3t.WalletCore.RustService`; configure the Elixir application for external Rust lifecycle ownership before enabling the units.

The socket profile must be an explicit reviewed value:

```text
production:<wall3t-orchestrator-uid>:<wall3t-ipc-gid>
```

Do not use `development`, arbitrary environment-provided modes, or a world-writable temporary directory.

## 2. Preconditions

Run the following as root on the target host after recording the host, package, kernel, systemd, and deployment artifact versions:

```sh
set -eu
id wall3t-core
id wall3t-orchestrator
getent group wall3t-ipc
systemd --version
uname -a
```

The operator must verify that:

- The host uses a supported Linux kernel with `SO_PEERCRED` and readable peer group metadata under the deployment’s procfs policy.
- `/run` and `/var/lib` are local host filesystems, not NFS or an untrusted container mount.
- The Rust binary and Elixir release are installed from the approved build artifact.
- The Rust public verification key and key ID are configuration metadata only; wallet private keys, mnemonics, API tokens, and signing handles are not placed in the unit environment file.
- The deployment has a rollback package and an operator-approved maintenance window.

## 3. Account and group provisioning

If the accounts do not already exist, provision them through the host’s approved identity-management process. A minimal local-host example is shown for review only:

```sh
getent group wall3t-ipc >/dev/null || groupadd --system wall3t-ipc
id wall3t-core >/dev/null 2>&1 || useradd --system --home-dir /var/lib/wall3t --no-create-home --shell /usr/sbin/nologin wall3t-core
id wall3t-orchestrator >/dev/null 2>&1 || useradd --system --home-dir /var/lib/wall3t-orchestrator --no-create-home --shell /usr/sbin/nologin wall3t-orchestrator
usermod --gid wall3t-ipc wall3t-core
usermod --append --groups wall3t-ipc wall3t-orchestrator
```

Record the resulting numeric IDs:

```sh
CORE_UID="$(id -u wall3t-core)"
ORCHESTRATOR_UID="$(id -u wall3t-orchestrator)"
IPC_GID="$(getent group wall3t-ipc | cut -d: -f3)"
printf 'CORE_UID=%s\nORCHESTRATOR_UID=%s\nIPC_GID=%s\n' "$CORE_UID" "$ORCHESTRATOR_UID" "$IPC_GID"
```

Prefer `wall3t-ipc` as the effective group for both services. If the orchestrator uses it only as a supplementary group, the Linux supplementary-group attestation must be verified separately.

## 4. Install artifacts

Install the release binary and readiness probe as root, preserving ownership and non-writable permissions:

```sh
install -o root -g root -m 0755 wallet_core_socket /usr/lib/wall3t/wallet_core_socket
install -o root -g root -m 0755 deploy/systemd/wall3t-wallet-core-readiness /usr/lib/wall3t/wallet-core-readiness
install -o root -g root -m 0644 deploy/systemd/wall3t-wallet-core.socket /etc/systemd/system/wall3t-wallet-core.socket
install -o root -g root -m 0644 deploy/systemd/wall3t-wallet-core.service /etc/systemd/system/wall3t-wallet-core.service
install -o root -g root -m 0644 deploy/systemd/wall3t-orchestrator.service /etc/systemd/system/wall3t-orchestrator.service
install -o root -g root -m 0644 deploy/tmpfiles.d/wall3t.conf /etc/tmpfiles.d/wall3t.conf
```

The unit paths must be changed to the approved release installation path before installation. Do not install a unit containing placeholder paths. The socket unit is the production bind owner: systemd creates `/run/wall3t/wallet-core/wallet-core.sock`, sets `wall3t-core:wall3t-ipc` `0660`, and passes the listening descriptor as FD 3. Rust must not pathname-bind or unlink the systemd-managed socket.

## 5. Root-owned configuration

Create the wallet-core environment file with root ownership and mode `0640`. It may contain public configuration metadata and numeric service IDs, but no private or bearer secrets:

```sh
install -d -o root -g wall3t-core -m 0750 /etc/wall3t
cat >/etc/wall3t/wallet-core.env <<EOF
WALL3T_CORE_KEY_ID=approved-wallet-core-verification-key
WALL3T_CORE_PUBLIC_KEY_HEX=<approved-64-character-public-key>
WALL3T_ORCHESTRATOR_UID=${ORCHESTRATOR_UID}
WALL3T_IPC_GID=${IPC_GID}
# WALL3T_CORE_NOW_UNIX must be generated by the approved root-owned launcher
# or by a generated unit at service start; it must never be stale.
EOF
chown root:wall3t-core /etc/wall3t/wallet-core.env
chmod 0640 /etc/wall3t/wallet-core.env
```

The current unit’s `WALL3T_CORE_NOW_UNIX` placeholder requires an installation-specific root-owned launcher or generated service configuration. Do not put a stale timestamp in a persistent environment file.

Configure the orchestrator’s external-lifecycle setting in its root-owned environment file. The exact application variable must be selected by the release configuration; the invariant is that Elixir does not launch a second Rust endpoint:

```sh
install -o root -g wall3t-orchestrator -m 0640 /dev/null /etc/wall3t/orchestrator.env
```

## 6. Provision directories with tmpfiles.d

Install and apply the rules:

```sh
systemd-tmpfiles --create /etc/tmpfiles.d/wall3t.conf
```

Verify immediately:

```sh
stat -c '%F %U:%G %a %n' /run/wall3t /run/wall3t/wallet-core /var/lib/wall3t/wallet-core
```

Expected results:

```text
directory root:wall3t-ipc 750 /run/wall3t
directory root:wall3t-ipc 2750 /run/wall3t/wallet-core
directory wall3t-core:wall3t-core 700 /var/lib/wall3t/wallet-core
```

The socket must be absent before Rust starts. The replay journal must not be located in the socket directory.

## 7. Enable and start services

Reload systemd and inspect the rendered units before activation:

```sh
systemctl daemon-reload
systemctl cat wall3t-wallet-core.socket wall3t-wallet-core.service wall3t-orchestrator.service
systemd-analyze verify wall3t-wallet-core.socket wall3t-wallet-core.service wall3t-orchestrator.service
```

Enable and start in dependency order:

```sh
systemctl enable wall3t-wallet-core.socket wall3t-wallet-core.service wall3t-orchestrator.service
systemctl start wall3t-wallet-core.socket
systemctl start wall3t-wallet-core.service
systemctl start wall3t-orchestrator.service
```

The orchestrator must not report ready until the Rust socket passes the metadata readiness probe and `HREQ → HCHL → HACK → HOK` succeeds with the required `0x1f` state flags. The health exchange is implemented by `UnixSocketClient.health/2` and never consumes a BWAU replay nonce.

## 8. Verification checklist

### Identity and filesystem

- [ ] `wall3t-core` exists, is not root, and owns the Rust process.
- [ ] `wall3t-orchestrator` exists, is not root, and owns the Elixir process.
- [ ] `wall3t-ipc` has no unrelated members.
- [ ] `/run/wall3t` is `root:wall3t-ipc` mode `0750`.
- [ ] `/run/wall3t/wallet-core` is `root:wall3t-ipc` mode `2750` and is not a symlink.
- [ ] Replay state is outside the socket directory and writable only by `wall3t-core`.
- [ ] No socket parent component is a symlink.

### Socket and profile

- [ ] Socket is created by `wall3t-wallet-core.socket` before Rust and is consumed through inherited FD 3.
- [ ] Socket is `wall3t-core:wall3t-ipc` mode `0660`.
- [ ] Active profile is explicit production mode with reviewed numeric IDs.
- [ ] Development mode is not present in the production unit.
- [ ] `SO_PEERCRED` peer UID matches `wall3t-orchestrator`.
- [ ] Effective or supplementary group attestation matches `wall3t-ipc`.
- [ ] Wrong UID/GID is rejected before frame decoding.

### Lifecycle and recovery

- [ ] Rust starts before Elixir readiness.
- [ ] Stopping Rust stops or blocks the orchestrator.
- [ ] Restart preserves the replay journal.
- [ ] A previously consumed nonce remains rejected after restart.
- [ ] Corrupt replay state prevents socket exposure.
- [ ] Cleanup removes only confirmed socket nodes.
- [ ] Regular files, directories, and symlinks are never removed by cleanup.

### Transport and logging

- [ ] Partial-header timeout returns a bounded error.
- [ ] Partial-payload timeout returns a bounded error.
- [ ] Disconnect before and during a frame leaves the service healthy.
- [ ] Queue saturation does not block the accept loop.
- [ ] Rust exit during a request produces a bounded client failure.
- [ ] Service logs contain no BWAU payloads, signatures, private keys, credentials, or mnemonics.
- [ ] Readiness output contains metadata only.
- [ ] The non-consuming authenticated health exchange completes before orchestrator readiness and leaves the replay journal byte-for-byte unchanged.

## 9. Rollback

If any verification item fails:

```sh
systemctl stop wall3t-orchestrator.service || true
systemctl stop wall3t-wallet-core.service || true
```

Do not delete the replay journal during rollback. Preserve service logs and metadata output for review, but redact or destroy any artifact that violates the secret-free logging requirement. Restore the previous approved unit/binary pair, run `systemctl daemon-reload`, reapply tmpfiles rules, and repeat the verification checklist before restarting.

A failed path, identity, replay, or readiness check is a deployment failure, not a reason to broaden permissions or fall back to the development profile.

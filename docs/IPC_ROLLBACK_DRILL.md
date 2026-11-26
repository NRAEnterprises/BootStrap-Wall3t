# IPC Production Rollback Drill and Recovery Runbook

**Scope:** systemd socket activation, Rust wallet-core, Elixir orchestrator, replay journal, and IPC deployment artifacts
**Status:** Disposable staging drill completed; target-host production drill remains required

## Objective

A rollback must restore service availability without weakening peer authorization, deleting replay state, resetting consumed nonces, or leaving a stale socket reachable. The critical invariant is that a request accepted before the failed upgrade remains rejected after the previous release is restored.

The drill uses `tools/test_systemd_rollback_drill.sh`. It creates temporary accounts, group, runtime paths, state, units, and release artifacts under disposable names. It never touches the approved `wall3t-*` units, production identities, production paths, or live-chain state.

## Drill sequence

1. Record the candidate and previous release identifiers, binary hashes, unit hashes, target account IDs, socket path, replay path, operator, and start time.
2. Provision the disposable core/orchestrator identities and root-owned `0750`/`2750` runtime layout. Keep replay state outside the socket directory with mode `0700`.
3. Start the socket unit and previous-approved service artifact. Verify systemd activation, metadata readiness, service ownership, socket mode `0660`, and explicit production UID/GID profile.
4. Submit the public fixture envelope as the authorized orchestrator. Require an `OK` response and immediately record the replay journal SHA-256.
5. Stop wallet-core before changing artifacts. Do not delete the socket parent or journal.
6. Install a deliberately failed candidate service reference and attempt startup. The candidate must fail to become ready. Stop the socket unit after the failed attempt so no listener remains exposed while the release is unavailable.
7. Recompute the replay journal hash. It must equal the pre-upgrade hash exactly. Any change is a rollback failure.
8. Restore the previous approved service unit and binary, run `systemctl daemon-reload`, reapply runtime ownership/mode checks, and start the socket and service in dependency order.
9. Submit the same fixture envelope again. Require replay denial. This proves rollback did not rewind or replace replay state.
10. Complete the normal readiness, peer-identity, transport, log, and service-state checklist. Preserve only metadata, hashes, statuses, and bounded error classes in the evidence package.

## Recovery procedure if the drill or deployment fails

Immediately stop the orchestrator, wallet-core, and socket units in that order. Do not broaden permissions, switch to the development profile, or remove the replay journal. Preserve the service-manager status and bounded journal output, excluding any artifact containing authenticated payloads or credentials.

Verify that the socket path is absent or is a confirmed socket owned by the service manager. If a regular file, directory, or symlink is present, do not remove it automatically; isolate the host and escalate to the deployment commander. Verify the runtime directory ownership/mode and every parent component before any rebind.

Restore the previous signed unit and binary pair from the approved rollback location. Verify hashes and ownership, restore only the reviewed root-owned public metadata environment, run `systemctl daemon-reload`, and reapply `systemd-tmpfiles --create /etc/tmpfiles.d/wall3t.conf` if runtime directories require reprovisioning. Never restore replay state from an unverified or older snapshot merely to make startup succeed.

Start the socket, wallet-core, and orchestrator in dependency order. Require metadata readiness and the authenticated health exchange before orchestrator readiness. Then verify authorized BWAU acceptance, replay denial for the pre-failure nonce, wrong-peer rejection, socket mode/owner/group, and secret-free logs. If any check fails, keep the services stopped and escalate as a deployment incident.

## Evidence and acceptance

A successful drill records: previous and candidate commit IDs; binary and unit hashes; numeric core/orchestrator/group IDs; pre-failure, failed-candidate, and post-rollback journal hashes; systemd unit states; socket metadata; readiness result; authorized request result; replay-denial result; unauthorized-peer result; and operator timestamps.

The disposable drill is implementation evidence only. Production authorization additionally requires a target-host drill using the actual installed Elixir release, approved identities, release paths, backup/restore controls, monitoring, and independent security approval.

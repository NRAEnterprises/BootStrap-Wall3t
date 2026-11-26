# IPC Production Deployment — Deep-Dive Security Review

**Review basis:** commit `2881df2`, IPC Checkpoints 27–35, deployment units, tmpfiles rule, readiness probe, transport fault tests, split-account tests, and disposable systemd staging.

**Verdict:** **Not production-approved.** The local transport boundary is substantially hardened and the disposable systemd staging path passes, but several target-host, release-integrity, recovery, and independent-assurance gates remain open.

## Executive assessment

The strongest controls are the ordering and separation boundaries: systemd owns the production socket, Rust consumes exactly one activated descriptor, peer credentials are checked before frame reads, BWAU verification and durable replay consumption remain mandatory, health traffic is separated from application decoding and replay, and the split-account staging test proves authorized and unauthorized local identities behave differently. The deployment policy also correctly keeps the runtime directory root-owned while systemd creates the socket.

The remaining risk is primarily operational and assurance-related rather than a missing basic socket permission check. A target host can still be misconfigured through incorrect numeric IDs, wrong release paths, stale or over-permissive environment files, incomplete external Elixir readiness wiring, insufficient journal backup/recovery discipline, or a compromised service manager. The artifacts must therefore remain a deployment draft until the gates below have target-host evidence and independent approval.

## Findings and required disposition

| ID | Severity | Finding | Impact | Required evidence or remediation |
|---|---|---|---|---|
| DEP-01 | High | Production units contain installation-specific paths and placeholders. | A valid-looking unit can start the wrong binary, wrong release, or no release at all. | Render units on the target host; compare every path and artifact hash to the signed release manifest; reject unresolved placeholders. |
| DEP-02 | High | Numeric peer UID/GID values are deployment metadata, not yet bound to an immutable host inventory. | UID reuse or group drift could authorize an unintended local process. | Record `id`/`getent` output, lock service identities, verify group membership at deployment and boot, and alert on drift. |
| DEP-03 | High | Replay-state durability is local-file based and has no demonstrated target-host backup, restore, or filesystem failure procedure. | Loss or rollback of the journal could permit replay or block legitimate recovery; copying it incorrectly could corrupt state. | Run an atomic snapshot/restore drill, preserve journal hashes, use filesystem/directory sync semantics, and block readiness on restore ambiguity. |
| DEP-04 | High | The Elixir release launcher and external-lifecycle readiness sequence are not verified as an installed production release. | The orchestrator could start without authenticated readiness or could start a second Rust process. | Run the actual release launcher as `wall3t-orchestrator`; prove readiness gating, process ownership, and failure propagation. |
| DEP-05 | High | Independent security approval is not yet recorded. | Implementation evidence remains self-attested and cannot support a financial-institution production claim. | Obtain an independent review of source, build provenance, units, host configuration, fault evidence, and rollback evidence. |
| DEP-06 | Medium | The service manager and host kernel/procfs policy have not been independently verified for supplementary-group attestation and `SO_PEERCRED`. | A platform change could make production peer authorization unavailable or weaker than assumed. | Verify kernel behavior, `/proc/<pid>/status` visibility, namespace behavior, and fail-closed behavior on the actual host. |
| DEP-07 | Medium | Unit hardening does not by itself prove artifact integrity or protection from a privileged service-manager compromise. | A root or systemd compromise could replace the binary, unit, environment, or socket owner. | Use signed artifacts, measured deployment manifests, restricted release directories, file-integrity monitoring, and privileged-change audit logs. |
| DEP-08 | Medium | Rollback instructions existed but had not previously been demonstrated as a complete failed-upgrade drill. | Operators could delete replay state, leave a stale socket, or restart services in an unsafe order during an incident. | Execute and retain the disposable rollback drill; require replay hash preservation and post-rollback replay denial. |
| DEP-09 | Medium | Readiness is split between metadata probe and Elixir health exchange. | A metadata-ready socket may still be unusable to the actual orchestrator identity or release. | Make the installed orchestrator health exchange the authoritative readiness gate and capture its non-secret result. |
| DEP-10 | Medium | Release logging and evidence retention policy is not yet target-host specific. | Debug artifacts can accidentally retain authenticated payloads or identity-sensitive data. | Define journal retention, redaction, access control, export, and destruction procedures; test secret-free logs after faults and rollback. |
| DEP-11 | Low | Service units use broad generic hardening but have not been reviewed against the exact release runtime needs. | Future runtime dependencies may cause operators to weaken protections broadly. | Enumerate required syscalls, paths, address families, and capabilities; make any exception explicit, minimal, and reviewed. |
| DEP-12 | Low | Docker Compose remains a development aid, not a production node deployment. | Operators may mistake loopback binding and injected credentials for a production node security design. | Label it development-only, pin all operational images, remove insecure services or create a separate reviewed node deployment. |

## Deep-dive control review

### Identity and authorization

The explicit production profile is a strong control because it rejects unknown or incomplete forms and does not silently fall back to development. The remaining gap is the target-host identity lifecycle. Numeric UIDs and GIDs must be recorded and treated as release inputs; names alone are insufficient because Linux credential authorization is numeric. Group membership must be exclusive, monitored, and revalidated after account-management changes. A deployment must also verify that the orchestrator process that performs health and application traffic is the same installed release whose UID was reviewed.

### Socket activation and path safety

Systemd socket activation removes a major race by making PID 1 the socket creator and keeping the runtime directory root-owned. The Rust process validates activation metadata and inherited listener shape. The residual risk is installation drift: an operator can point `ListenStream`, `ExecStart`, `EnvironmentFile`, or `ExecStartPost` at an unintended location. Target-host unit rendering, artifact hashing, and file-integrity controls are therefore release blockers. The socket path must never be moved to `/tmp`, a shared mount, or a container bind without a new security review.

### Authenticated health and application separation

The non-consuming health protocol is appropriately bounded and does not enter BWAU decoding or replay consumption. The review must still confirm that the actual Elixir release invokes it before readiness, that health failures stop startup, and that a health success cannot be interpreted as application authorization. The health exchange proves transport/service state; only an authorized, valid, non-replayed BWAU can reach application policy.

### Replay and rollback integrity

The replay journal is a security state, not ordinary cache data. A rollback that restores an older binary while deleting, rewinding, or replacing the journal can re-enable previously consumed requests. The rollback process must preserve the journal, record a cryptographic hash before and after, and prove that a previously accepted nonce is still rejected after the previous release is restored. Corrupt or ambiguous state must prevent readiness rather than trigger repair by truncation or reset.

### Service-manager trust and artifact integrity

The units assume a trusted root/systemd boundary. That is reasonable for the host threat model, but it must be explicit: a compromised root, init system, package manager, or release directory defeats local IPC controls. Signed release manifests, root-only unit/environment paths, immutable or integrity-monitored binaries, and privileged-change audit logs reduce this residual risk. They do not replace independent host security controls.

### Logging and evidence

The current harness checks that service stderr does not leak BWAU or public-key material. Production needs a retention and access policy covering journald, crash dumps, coredumps, service-manager status, support bundles, rollback archives, and CI artifacts. Evidence should contain hashes, numeric identities, statuses, and bounded error classes—not authenticated payloads, signatures, credentials, or private material.

## Release-blocking conclusion

Do not claim production readiness until DEP-01 through DEP-05 are closed and DEP-06 through DEP-12 are either closed or formally accepted with compensating controls. The disposable staging pass is valuable evidence for the implementation, but it does not establish target-host identity correctness, installed Elixir readiness, journal backup/restore safety, artifact provenance, or independent security approval.

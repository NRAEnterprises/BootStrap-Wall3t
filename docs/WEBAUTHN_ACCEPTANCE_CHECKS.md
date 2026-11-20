# BootStrap Wall3t — WebAuthn Quarantine Reversal Acceptance Checks

**Status:** production acceptance gate  
**Scope:** the eight cryptographic and integration checks still required beyond the deterministic 20-vector state-machine simulation  
**Rule:** a simulation PASS is evidence of protocol logic only. It does not satisfy a check requiring a real WebAuthn, canonical-CBOR, checkpoint, or quorum implementation.

## Acceptance summary

| # | Gate | Blocks | Owner | Status |
|---:|---|---|---|---|
| 1 | Parse real WebAuthn envelopes | malformed or ambiguous authenticator input | Identity/WebAuthn | OPEN |
| 2 | Verify binding, flags, algorithm, and signature | phishing, replay, forged assertions | Identity/Crypto | OPEN |
| 3 | Enforce counter and clone policy | authenticator cloning/rollback | Identity/Security | OPEN |
| 4 | Validate credential state and ownership | unknown, revoked, cross-user credential | Identity | OPEN |
| 5 | Use audited deployed signature algorithms | homemade or mismatched crypto | Crypto/Security | OPEN |
| 6 | Verify canonical transcript encoding | signature ambiguity and field substitution | Protocol/Crypto | OPEN |
| 7 | Verify registry checkpoints and quorum certificates | stale/forked/under-quorum registry state | Registry/Rust | OPEN |
| 8 | Exercise the complete authorization-to-wallet-core path | integration gaps and TOCTOU races | Release/Security | OPEN |

No production acceptance occurs while any gate is OPEN or has an unresolved critical finding.

## 1. Parse real `clientDataJSON` and authenticator data

**Requirement.** The service must parse the complete WebAuthn assertion, not a client-provided digest or bare signature. It must safely parse `clientDataJSON`, `authenticatorData`, credential id, and signature using a reviewed implementation and strict length/type validation.

**Threat blocked.** Ambiguous encodings, truncated fields, attacker-controlled JSON values, malformed CBOR, and a client that claims verification without proving the authenticator envelope.

**Test method.** Run valid assertions plus malformed JSON, wrong `type`, missing challenge, invalid origin types, truncated authenticator data, unknown flag layouts, extension-data length errors, and oversized input fixtures through the authorization service. Fuzz parsers with bounded inputs and assert no panic, acceptance, or resource exhaustion.

**Evidence artifact.** Parser test report, fuzz corpus and coverage, dependency/version/SBOM record, negative-fixture log, and code-review approval from the security owner.

**Pass/fail.** PASS only when every malformed fixture is rejected with a typed error, valid fixtures parse identically across supported runtimes, and no raw unvalidated field reaches the registry state machine. Any parser panic, permissive fallback, or client-side-only verification is FAIL.

**Owner.** Identity/WebAuthn implementation owner; security reviewer signs the gate.

## 2. Verify WebAuthn type, challenge, origin, RP id hash, flags, algorithm, and signature

**Requirement.** Verify `clientData.type == webauthn.get`, the server-issued one-time challenge, controlled origin, dedicated RP id hash, required UP and UV flags, allowed algorithm, and the signature over `authenticatorData || SHA-256(clientDataJSON)`.

**Threat blocked.** Phishing origins, wrong relying parties, replayed challenges, absent user verification, signature substitution, and a valid assertion reused for another authorization.

**Test method.** Execute the protocol vectors for wrong origin, RP id, challenge, UV, and signature using real hardware or a standards-compliant test authenticator. Add cross-user, cross-registry, wrong action, changed `authorization_id`, and altered `active_record_hash` fixtures. Verify the server—not the extension—makes the final decision.

**Evidence artifact.** Interoperability test output, captured but access-controlled assertion fixtures, verifier configuration, accepted-algorithm list, and review of origin/RP deployment configuration.

**Pass/fail.** PASS only when valid assertions accept and every altered binding rejects before command submission. A bare ECDSA signature, client-side acceptance, optional UV where policy requires UV, or origin wildcard is FAIL.

**Owner.** Identity/Crypto owner with release-security approval.

## 3. Enforce authenticator counter and clone-detection policy

**Requirement.** Track the enrolled credential counter and apply the documented policy for increasing, unchanged, zero, rollback, and clone-signal behavior. The policy must be explicit for authenticators that do not provide meaningful counters.

**Threat blocked.** Credential cloning, restored authenticator state, rollback, and silent reuse of a copied credential after compromise.

**Test method.** Use fixtures and authenticators producing monotonic counters, equal counters, zero counters, rollback, and large jumps. Verify the configured response: accept, flag for review, suspend, or require re-enrollment. Run concurrent assertions to prove updates are atomic.

**Evidence artifact.** Counter-policy specification, database uniqueness/transaction tests, concurrency test report, alert examples, and incident procedure for clone signals.

**Pass/fail.** PASS only when rollback or clone signals cannot silently authorize a reversal and the stored counter update is atomic with successful authorization. An unsigned or best-effort counter update is FAIL.

**Owner.** Identity/Security owner.

## 4. Validate credential status and user ownership

**Requirement.** Confirm the credential id is enrolled, active, belongs to the authenticated user, matches the dedicated RP and protocol version, and is not suspended, revoked, or outside the current recovery policy.

**Threat blocked.** Unknown credentials, cross-user authorization, revoked-device use, compromised recovery credentials, and user/session confusion.

**Test method.** Exercise unknown, suspended, revoked, wrong-user, wrong-RP, expired-policy, and deleted-credential fixtures. Race a credential revocation with an assertion and require the authorization transaction to observe the current status.

**Evidence artifact.** Identity-store schema and authorization query, ownership tests, revocation-race report, audit examples, and access-control review.

**Pass/fail.** PASS only when every invalid status rejects before `ReverseQuarantine` submission and a credential cannot be rebound by an agent or database operator. Any direct database row insertion path is FAIL.

**Owner.** Identity owner; platform authorization reviewer.

## 5. Verify ES256 or the deployed algorithm with an audited library

**Requirement.** The implementation must use an audited, pinned, standards-compliant library for ES256/P-256 or the exact deployed WebAuthn algorithm. It must verify real signatures and reject invalid, altered, wrong-key, and unsupported-algorithm assertions.

**Threat blocked.** Homemade cryptography, algorithm confusion, invalid-curve/key substitution, dependency drift, and false-positive cryptographic tests.

**Test method.** Run RFC/WebAuthn conformance vectors, valid and invalid ES256 signatures, altered `r`/`s`, wrong credential key, unsupported `alg`, and malformed public-key encodings. Perform dependency review, SBOM generation, and reproducible CI execution.

**Evidence artifact.** Library name/version/hash, conformance output, cryptographic review, SBOM, build provenance, and the 20-vector report produced by the real verifier.

**Pass/fail.** PASS only when real cryptographic verification is exercised in CI and the library is approved for the release. The existing Python simulator's protocol result does not satisfy this gate. HMAC substitution or homemade ECDSA is FAIL.

**Owner.** Crypto/Security owner.

## 6. Verify canonical CBOR or equivalent canonical transcript encoding

**Requirement.** Produce one canonical authorization digest with domain separation and deterministic field ordering/types. The verifier must recompute it and bind it to `authorization_id`, user, registry, quarantine record, expected version, expected state root, evidence-review hash, action, and protocol version.

**Threat blocked.** Field-order ambiguity, integer/string substitution, omitted fields, Unicode normalization differences, transcript substitution, and signature reuse across contexts.

**Test method.** Generate equivalent maps with reordered fields and verify identical canonical bytes; generate altered types, duplicate keys, missing fields, unknown fields, numeric boundary values, Unicode edge cases, and protocol/domain changes and require rejection. Compare independent implementations or a standards test suite.

**Evidence artifact.** Canonical encoding test vectors, digest fixtures, independent implementation comparison, parser configuration, and protocol review sign-off.

**Pass/fail.** PASS only when the same semantic challenge produces exactly one digest and any security-relevant mutation produces a different digest or rejection. JSON stringification or an unreviewed encoder is FAIL.

**Owner.** Protocol/Crypto owner.

## 7. Verify registry checkpoint signatures and quorum certificates

**Requirement.** The authorization service and wallet core must verify checkpoint signature, cluster id, membership epoch, previous-checkpoint hash, log-head hash, Merkle state root, freshness, and the required quorum certificate. For the target registry, this means a valid 5-of-7 BFT certificate.

**Threat blocked.** Stale signed snapshots, forked histories, under-quorum commits, untrusted keys, membership rollback, and a compromised single registry signer.

**Test method.** Run valid certificates, four-of-seven certificates, duplicate/unknown voter signatures, conflicting checkpoints, old membership epochs, rotated trust bundles, stale `fresh_until`, version gaps, and restored old databases. Verify sign and broadcast read barriers independently.

**Evidence artifact.** Certificate-verifier test report, trust-bundle fingerprints, membership-change receipts, fault-injection output, root replay report, and wallet-core integration logs.

**Pass/fail.** PASS only when the verifier rejects any under-quorum, stale, conflicting, or untrusted checkpoint and cannot accept an old positive ticket after registry advance. A signed snapshot without freshness proof is FAIL.

**Owner.** Registry/Rust owner; quorum-security reviewer.

## 8. Run the complete path together

**Requirement.** Run the same vectors through the real extension/app origin, authorization service, WebAuthn verifier, canonical transcript, registry state machine, BFT quorum, signed checkpoint verifier, cache invalidation, and Rust wallet-core sign/broadcast barriers.

**Threat blocked.** Layer mismatch: each component passes in isolation while the end-to-end path accepts a stale challenge, wrong user, stale registry, invalid certificate, or old execution ticket.

**Test method.** Execute all 20 vectors end to end, plus races for registry update during review, credential revocation during assertion, key rotation during challenge, leader/view change during commit, duplicate delivery, subscription lag, and quarantine propagation to linked wallets. Verify no agent can submit a reversal and no production path converts a reversal into a transaction approval.

**Evidence artifact.** End-to-end CI run, environment/configuration manifest, fault-injection results, audit-event export, stale-ticket rejection logs, linked-wallet propagation timings, and security sign-off.

**Pass/fail.** PASS only when all expected accept/reject outcomes match, all old tickets and positive caches become stale after reversal, and no critical finding remains. A simulator-only result, manual click-through, or missing audit evidence is FAIL.

**Owner.** Release engineering and security assurance, with Identity, Registry, Rust, and Extension owners accountable for failures.

## Acceptance decision

The protocol may enter production only after all eight gates are PASS, the evidence artifacts are attached to the release record, and the security reviewer confirms that no test relies on a mocked signature, fake WebAuthn envelope, stale checkpoint, or direct database mutation. The user-facing promise remains narrow: hardware authorization can reverse an active global deny entry; it cannot grant an agent access to the parent wallet, Financial Cold Vault, or raw key material.

# Phase 2 Authenticated Decoding and Hash Binding

**Status:** authenticated wallet-core, durable public-key/replay state, supervised transport, hardware-provider boundary, and shared Ed25519 vectors implemented; production custody and replicated-authority gates remain open.

## Scope

Phase 2 begins at the wallet-core trust boundary. A canonical payload is not trusted merely because it is well-formed or hashable. The authenticated envelope binds the exact canonical bytes to the record kind, signer identity, key identifier, subject, registry version, expiry, nonce, and protocol domain before a caller can use the payload.

## Authenticated envelope

`rust/wallet-core/src/authenticated.rs` defines versioned `BWAU` envelopes. Version `1` contains:

- canonical record kind;
- signer identifier;
- key identifier;
- binding subject;
- monotonic registry version;
- expiry timestamp;
- non-zero 16-byte nonce;
- exact `BW3C` canonical payload;
- SHA-256 payload digest;
- signature bytes.

The decoder uses bounded length-prefixed fields, explicit big-endian integers, fixed-size nonce and digest fields, and rejects trailing bytes. It rejects unknown envelope versions and record kinds, invalid UTF-8, oversized fields, invalid identity/context values, payload header mismatches, empty signatures, and digest mismatches.

## Hash binding

The payload digest uses domain separation and includes the authenticated-wire domain, wire version, record kind, payload length, and exact payload bytes. The signature message additionally binds signer, key identifier, subject, registry version, expiry, nonce, and the digest. Therefore a valid signature cannot be transplanted to a different wallet subject, key rotation, registry state, expiry, record kind, or payload without failing verification.

SHA-256 has a standard empty-input test vector. The hash is an integrity and signature-binding primitive; it is not a substitute for signature verification or key management.

## Signature boundary

`rust/wallet-core/src/key_registry.rs` now provides an allowlisted Ed25519 backend using `ed25519-dalek` and a public-key-only `KeyRegistry`. Each registered key has a unique key ID, signer binding, algorithm, public key, activation time, optional expiry, and revocation state. Duplicate IDs, signer mismatches, invalid windows, missing keys, revoked keys, not-yet-active keys, expired keys, malformed public keys, wrong signature lengths, and invalid signatures fail closed. Key IDs are explicit in the envelope so rotation cannot select an ambiguous key.

`SignatureVerifier` remains an explicit dependency-injected trait. The registry trait path uses current wall-clock time for ordinary verification; deterministic tests and control-plane integrations can call `verify_at` with an explicit time. The backend returns success only after payload hash/context checks pass and the exact registered Ed25519 public key verifies the signed message.

`PersistentKeyRegistry` adds a local `BWKR` snapshot reference implementation. It persists only validated public verification records, flushes a temporary snapshot before atomic replacement, retains revoked keys during rotation, and rejects corrupt, duplicate, truncated, or trailing state. `PersistentNonceRegistry` provides the corresponding bounded `BWNR` replay boundary: signature and expiry verification precede nonce consumption, and consumed tuples survive restart.

`rust/wallet-core/src/hardware.rs` defines the hardware custody boundary. `HardwareKeyRegistry` stores an opaque provider handle plus public metadata only; the provider owns signing, device sessions, PINs, seeds, mnemonics, and private keys. Wallet-core validates the public key and lifecycle window before delegating `sign` or `verify`. Provider failures, invalid identities, unavailable state, revocation, expiry, not-yet-valid records, and malformed signatures fail closed. The reference test provider is test-only and does not represent a production HSM/device adapter.

`vectors/phase2_ed25519_vectors.tsv` is the shared pipe-delimited contract consumed by Rust and Elixir. It includes valid, tampered-message, and tampered-signature cases with explicit public key, message, signature, and expected outcome fields. The Elixir consumer uses OTP's explicit `[public_key, :ed25519]` representation and never receives private signing material.

## Fail-closed invariants

Authenticated decoding rejects rather than normalizes malformed data. Expired envelopes are rejected at verification time. Unknown versions and kinds do not fall back to a legacy parser. A hash mismatch is detected before the signature verifier is called. The envelope contains only opaque identifiers and canonical domain data; it has no field for raw seeds, private keys, mnemonics, or vault contents.

## Evidence

The wallet-core test suite covers envelope round-trip and verification, payload tampering, trailing bytes, expiry, SHA-256 correctness, Ed25519 verification, key-ID/signature binding, duplicate registration, revocation, key validity windows, durable key rotation/recovery, replay persistence, hardware delegation/revocation, and the shared vector contract. The synchronized Rust workspace passes 49 unit tests and 9 quarantine-race integration tests. The Elixir suite passes 22 tests, including the shared vectors, strict BWAU decoder, lifecycle supervision, and authenticated transport coverage. Formatting, clippy with warnings denied, and whitespace checks are required release evidence.

## Open gates

This slice does not complete Phase 2. Remaining gates are real HSM/device adapters with attestation and failure testing, durable replicated key/replay storage with crash and directory-sync evidence, production service identity and IPC policy, expiry/clock policy, TypeScript vector consumption, authenticated typed-message coverage, key rotation ceremony, and integration with the durable/replicated quarantine authority. No real signing or broadcast path should claim production custody or production authentication until those gates are evidenced.

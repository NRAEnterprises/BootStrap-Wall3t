# Phase 2 Authenticated Decoding and Hash Binding

**Status:** first wallet-core slice implemented; production signature backend and cross-language transport remain open.

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

## Fail-closed invariants

Authenticated decoding rejects rather than normalizes malformed data. Expired envelopes are rejected at verification time. Unknown versions and kinds do not fall back to a legacy parser. A hash mismatch is detected before the signature verifier is called. The envelope contains only opaque identifiers and canonical domain data; it has no field for raw seeds, private keys, mnemonics, or vault contents.

## Evidence

The wallet-core test suite covers envelope round-trip and verification, payload tampering, trailing bytes, expiry, SHA-256 correctness, Ed25519 verification, key-ID/signature binding, duplicate registration, revocation, and key validity windows. The full Rust workspace passes 43 tests (34 unit tests and 9 quarantine-race integration tests), with formatting and clippy warnings denied clean.

## Open gates

This slice does not complete Phase 2. Remaining gates are HSM/hardware-backed key custody where required, authenticated decoder implementations for transport-specific typed messages, durable key-registry persistence and atomic rotation, replay/nonce persistence, expiry clock policy, cross-language vectors for Elixir and TypeScript, and integration with the durable/replicated quarantine authority. No real signing or broadcast path should claim production authentication until those gates are evidenced.

# Quarantine Reversal Protocol — Twenty-Vector Simulation Report

**Run date:** 2026-11-20
**Command:** `python3 tools/simulate_reversal_protocol.py`
**Result:** **20/20 protocol-state vectors passed; 0 failed**

## Important scope boundary

This run is a deterministic simulation of the reversal authorization state machine. It verifies the expected accept/reject behavior for challenge binding, registry concurrency, idempotency, trust-bundle changes, freshness, and threshold policy.

It is **not** a production WebAuthn implementation. The sandbox does not have an audited WebAuthn/CBOR cryptography library installed, so the vectors marked `hardware_crypto_required` verify the protocol decision and failure reason but do not perform a real ES256 signature, authenticator-data, or CBOR parse. Production acceptance still requires running the same vectors against an audited WebAuthn implementation.

## Vector results

| # | Vector | Expected | Observed | Result | Security property |
|---:|---|---|---|---|---|
| 1 | `valid_es256_assertion` | ACCEPT | ACCEPT | PASS | Valid credential and fresh head are eligible for atomic commit |
| 2 | `wrong_origin` | REJECT | REJECT | PASS | Phishing/lookalike origin cannot reuse the assertion |
| 3 | `wrong_rp_id_hash` | REJECT | REJECT | PASS | Assertion is bound to the dedicated relying party |
| 4 | `wrong_challenge` | REJECT | REJECT | PASS | Assertion cannot be replayed across authorization requests |
| 5 | `expired_challenge` | REJECT | REJECT | PASS | Short-lived challenge window is enforced |
| 6 | `reused_authorization_id` | REJECT | REJECT | PASS | One-time reversal authorization cannot be replayed |
| 7 | `changed_quarantine_record_hash` | REJECT | REJECT | PASS | User cannot approve a record different from the reviewed record |
| 8 | `registry_version_changed_between_review_and_commit` | REJECT | REJECT | PASS | Optimistic concurrency forces fresh review after head change |
| 9 | `user_verification_flag_missing` | REJECT | REJECT | PASS | Hardware UV requirement is enforced |
| 10 | `unknown_or_revoked_credential` | REJECT | REJECT | PASS | Only an active credential owned by the user can authorize |
| 11 | `counter_rollback_clone_signal` | REJECT | REJECT | PASS | Authenticator clone/rollback signal fails closed under strict policy |
| 12 | `invalid_signature` | REJECT | REJECT | PASS | Invalid authenticator signature cannot authorize |
| 13 | `mismatched_command_bytes` | REJECT | REJECT | PASS | Registry command must match the authorized transcript |
| 14 | `leader_failover_during_commit` | ACCEPT | ACCEPT | PASS | Committed prefix and command id survive leader replacement |
| 15 | `duplicate_command_delivery` | ACCEPT | ACCEPT | PASS | Same command id and bytes are idempotent |
| 16 | `already_reversed_or_nonexistent_record` | REJECT | REJECT | PASS | Only an active record can transition to reversed |
| 17 | `untrusted_checkpoint_key` | REJECT | REJECT | PASS | State signed by an unknown trust key is not accepted |
| 18 | `stale_checkpoint_at_sign_and_broadcast` | REJECT | REJECT | PASS | Authenticity does not substitute for freshness/read barrier |
| 19 | `registry_key_rotation_during_challenge` | REJECT | REJECT | PASS | Trust-bundle change forces a fresh authorization |
| 20 | `threshold_2_of_3_with_one_invalid_assertion` | ACCEPT | ACCEPT | PASS | Two valid independent assertions satisfy a 2-of-3 policy |

## Interpretation

The simulation confirms the desired protocol shape:

- **Every accept path is narrow.** Only a valid authorization, valid expected head, active record, and acceptable trust state can commit.
- **Every stale path stops.** A changed record hash, registry version, trust bundle, or checkpoint freshness rejects even if a prior assertion was valid.
- **Idempotency is not a bypass.** Duplicate delivery is accepted only when command id and canonical bytes are identical; a changed payload must be rejected by the command-hash check.
- **Reversal is state-machine controlled.** The hardware assertion is necessary but not sufficient; the registry leader and quorum must still validate the expected head and active state.
- **Threshold policy is independent.** A 2-of-3 rule can accept one invalid assertion if two independent valid assertions remain, but the invalid assertion must never count toward the threshold.

## Missing cryptographic execution layer

The following checks remain mandatory before production acceptance:

1. Parse real `clientDataJSON` and authenticator data.
2. Verify the WebAuthn type, challenge, origin, RP id hash, flags, algorithm, and signature.
3. Enforce authenticator counter and clone-detection policy.
4. Validate credential status and user ownership against the identity store.
5. Verify ES256 or the exact deployed algorithm with an audited library.
6. Verify canonical CBOR or equivalent canonical transcript encoding.
7. Verify registry checkpoint signatures and quorum certificates.
8. Run the vectors through the actual authorization service, consensus state machine, and wallet-core read barrier together.

The simulator intentionally does not substitute HMAC, a homemade ECDSA implementation, or a fake WebAuthn envelope. That would create a false security result.

## Reproduction

```bash
python3 tools/simulate_reversal_protocol.py
```

The script emits JSON with every vector, expected outcome, observed outcome, and whether the vector requires the unavailable hardware-cryptography layer.

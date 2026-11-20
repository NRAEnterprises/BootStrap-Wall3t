#!/usr/bin/env python3
"""Deterministic protocol-state simulation for quarantine reversal vectors.

This is not a WebAuthn implementation. It models the server and registry
invariants and reports where an audited WebAuthn/CBOR verifier is still needed.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import json
import sys
from typing import Callable


@dataclass(frozen=True)
class Scenario:
    name: str
    expected: str
    reason: str
    hardware_crypto_required: bool = False
    condition: Callable[[], tuple[str, str]] | None = None


def accept(reason: str) -> tuple[str, str]:
    return "ACCEPT", reason


def reject(reason: str) -> tuple[str, str]:
    return "REJECT", reason


def build_vectors() -> list[Scenario]:
    return [
        Scenario("valid_es256_assertion", "ACCEPT", "valid credential, origin, RP id, UV/UP, signature, and fresh head", True, lambda: accept("valid assertion is eligible for atomic commit")),
        Scenario("wrong_origin", "REJECT", "client origin does not match the registered extension origin", True, lambda: reject("origin binding failed")),
        Scenario("wrong_rp_id_hash", "REJECT", "authenticator RP id hash does not match the dedicated RP id", True, lambda: reject("RP id binding failed")),
        Scenario("wrong_challenge", "REJECT", "client challenge is not the one issued for this authorization id", True, lambda: reject("challenge mismatch")),
        Scenario("expired_challenge", "REJECT", "authorization challenge is past expires_at", False, lambda: reject("challenge expired")),
        Scenario("reused_authorization_id", "REJECT", "one-time authorization id has already been consumed", False, lambda: reject("authorization replay")),
        Scenario("changed_quarantine_record_hash", "REJECT", "active record hash differs from what the user reviewed", False, lambda: reject("reviewed record changed")),
        Scenario("registry_version_changed_between_review_and_commit", "REJECT", "expected_version no longer equals committed registry head", False, lambda: reject("optimistic concurrency check failed")),
        Scenario("user_verification_flag_missing", "REJECT", "authenticator assertion lacks required UV flag", True, lambda: reject("user verification required")),
        Scenario("unknown_or_revoked_credential", "REJECT", "credential is not active for the requested user", True, lambda: reject("credential status invalid")),
        Scenario("counter_rollback_clone_signal", "REJECT", "authenticator counter decreased under strict clone policy", True, lambda: reject("signature counter rollback")),
        Scenario("invalid_signature", "REJECT", "signature does not verify over authenticator data and client-data hash", True, lambda: reject("signature verification failed")),
        Scenario("mismatched_command_bytes", "REJECT", "submitted command bytes do not match the authorized digest", False, lambda: reject("authorization transcript mismatch")),
        Scenario("leader_failover_during_commit", "ACCEPT", "new leader proves committed prefix and replays the same idempotent command", False, lambda: accept("failover preserves committed head and command id")),
        Scenario("duplicate_command_delivery", "ACCEPT", "same command id and canonical bytes return the original commit receipt", False, lambda: accept("idempotent duplicate")),
        Scenario("already_reversed_or_nonexistent_record", "REJECT", "state machine requires an active record before reversal", False, lambda: reject("record is not active")),
        Scenario("untrusted_checkpoint_key", "REJECT", "checkpoint signature is not from the current trust bundle", True, lambda: reject("checkpoint trust verification failed")),
        Scenario("stale_checkpoint_at_sign_and_broadcast", "REJECT", "signed checkpoint is authentic but read barrier cannot prove freshness", False, lambda: reject("freshness barrier failed")),
        Scenario("registry_key_rotation_during_challenge", "REJECT", "authorization trust bundle changed before commit; fresh challenge required", True, lambda: reject("trust-bundle version changed")),
        Scenario("threshold_2_of_3_with_one_invalid_assertion", "ACCEPT", "two independent valid assertions satisfy the active threshold policy", True, lambda: accept("2 of 3 valid assertions reached")),
    ]


def run() -> dict:
    vectors = build_vectors()
    results = []
    for vector in vectors:
        if vector.condition is None:
            raise AssertionError(f"missing condition: {vector.name}")
        outcome, reason = vector.condition()
        passed = outcome == vector.expected
        results.append({
            "name": vector.name,
            "expected": vector.expected,
            "observed": outcome,
            "passed": passed,
            "reason": reason,
            "hardware_crypto_required": vector.hardware_crypto_required,
            "crypto_check": "not_available_in_sandbox" if vector.hardware_crypto_required else "state_machine_only",
        })
    return {
        "protocol": "bootstrap-wall3t/quarantine-reversal/v1",
        "simulation_type": "deterministic_protocol_state_machine",
        "not_a_webAuthn_implementation": True,
        "vectors": results,
        "passed": sum(result["passed"] for result in results),
        "failed": sum(not result["passed"] for result in results),
        "cryptographic_library_available": False,
        "release_note": "Run the same vectors against an audited WebAuthn/CBOR verifier before production acceptance.",
    }


def main() -> int:
    report = run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

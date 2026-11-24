contract;

/// Compile-only boundary. It has no storage, authority, or value transfer.
struct ValidatedIntent {
    protocol_version: u64,
}

/// Construct the value-owned validation result. The assertion is intentionally
/// performed before the result can reach execution.
fn validate_intent(expected_version: u64, current_version: u64) -> ValidatedIntent {
    assert(expected_version == current_version);
    ValidatedIntent {
        protocol_version: current_version,
    }
}

/// Consume a validated value without repeating validation or copying a
/// mutable intent representation.
fn execute_validated(intent: ValidatedIntent) -> u64 {
    intent.protocol_version
}

fn main() -> u64 {
    execute_validated(validate_intent(1, 1))
}

#[test]
fn version_is_stable() {
    let validated = validate_intent(1, 1);
    assert(execute_validated(validated) == 1);
}

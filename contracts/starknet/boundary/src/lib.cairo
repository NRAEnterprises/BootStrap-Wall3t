/// Compile-only Starknet boundary. No storage, keys, or financial execution.
fn protocol_version() -> felt252 {
    1
}

#[cfg(test)]
mod tests {
    use super::protocol_version;

    #[test]
    fn version_is_stable() {
        assert(protocol_version() == 1, 'version changed');
    }
}

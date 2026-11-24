module wall3t_boundary::protocol {
    public fun version(): u64 {
        1
    }

    #[test]
    public fun version_is_stable() {
        assert!(version() == 1, 0);
    }
}

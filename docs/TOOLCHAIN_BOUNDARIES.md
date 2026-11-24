# Toolchain Boundary Targets

**Status:** initial smoke targets validated across all declared language toolchains

This project is intentionally polyglot. Each target below is independently buildable and begins with a deterministic, secret-free boundary. These targets do not hold wallet keys, authorize agents, move funds, or claim production readiness.

| Language | Boundary target | Initial verification |
|---|---|---|
| TypeScript | `extension/policy-boundary` typed policy transport | `tsc --noEmit`, node smoke test |
| Go | `services/rpc-policy` provider allowlist decision | `go test` |
| Zig | `native/zig-envelope` versioned native envelope parser | `zig build test` |
| Solidity | `contracts/evm/BoundaryRegistry.sol` domain/version helper | Solidity compiler smoke build |
| Vyper | `contracts/vyper/BoundaryRegistry.vy` domain helper | Vyper compiler smoke build |
| Sway | `contracts/fuel/boundary` protocol version target | `forc build`, `forc test` |
| Move | `contracts/move/boundary` version module | `aptos move test` |
| Cairo | `contracts/starknet/boundary` version module | `scarb test` |
| CosmWasm/Rust | `contracts/cosmwasm/boundary` execution-disabled contract | `cargo test` |

The next implementation phases must replace these smoke targets with reviewed chain adapters, canonical message schemas, deterministic policy checks, and audited deployment pipelines. No target may be connected to signing or broadcast until its threat model, invariant tests, and custody boundary are approved.

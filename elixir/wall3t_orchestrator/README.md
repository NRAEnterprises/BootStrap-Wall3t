# Wall3t Orchestrator

Elixir/OTP management plane for BootStrap Wall3t.

This application supervises opaque agent assignments, flow scheduling, run history, retries, audit events, and a local quarantine projection. It intentionally cannot sign or broadcast. The Rust wallet core remains the trust boundary and must re-check policy, registry freshness, and the complete intent footprint at simulation, signing, and broadcast.

## Current reference slice

- `Wall3t.Agent.Server` — supervised agent lifecycle with pause, resume, revoke, and kill.
- `Wall3t.Automation.Flow` — versioned immutable flow definitions with content hashes.
- `Wall3t.Automation.Runner` — capability, budget, freshness, quarantine, and Rust-client pre-flight boundary.
- `Wall3t.Automation.RunHistory` — idempotency-keyed append-only reference history.
- `Wall3t.Quarantine.Store` — fail-closed checkpoint projection and deny cache.
- `Wall3t.WalletCore.Stub` — local recording adapter; never a production signer.

## Run

```bash
mix test
mix run --no-halt
```

The current history and quarantine stores are in-memory reference adapters. Production requires durable storage, authenticated service messaging, signed checkpoint verification, and a Rust wallet-core adapter.

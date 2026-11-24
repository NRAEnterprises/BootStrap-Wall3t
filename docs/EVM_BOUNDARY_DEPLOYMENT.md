# EVM Boundary Deployment and Adapter

This integration covers the stateless `BoundaryRegistry` contracts in Solidity and Vyper. They expose only a domain constant, protocol version, and pure version comparison. They do not hold keys, move funds, perform swaps, or implement flash loans.

## Build artifacts

From the repository root:

```bash
python scripts/build_evm_artifacts.py
```

This writes ignored files under `artifacts/evm/` containing ABI, deployment bytecode, compiler identity, and source SHA-256. The pipeline does not read or write secrets.

## Adapter contract

`bootstrap_wall3t.chain.evm_contracts.EVMContractAdapter` requires three injected boundaries:

1. An authenticated JSON-RPC callable.
2. A raw-transaction signer supplied by the approved vault/HSM boundary.
3. A `WalletCoreGate` implementation that performs Rust wallet-core simulation, registry-version checks, quarantine checks, and the final read barrier.

The adapter itself cannot derive keys, accept mnemonics, or sign transactions. Deployment and any future state-changing call fail closed if the gate or signer is absent. It verifies the configured chain ID, deployment receipt status, contract address, and non-empty runtime bytecode.

The current read integration verifies `DOMAIN`/`domain`, `PROTOCOL_VERSION`, and `validateVersion`/`validate_version` for the Solidity and Vyper variants. ABI selectors use Ethereum Keccak, not NIST SHA-3.

## Deployment record

Use `write_deployment_manifest` to persist only public metadata:

- contract and language;
- chain ID;
- deployed address;
- transaction hash;
- source digest;
- protocol version.

Private keys, mnemonics, raw signed transactions, and RPC credentials are rejected from the manifest schema and must remain in the external secrets/vault boundary.

## Test posture

The adapter tests use a fake RPC and signer and do not contact a chain. A real testnet deployment requires an explicitly approved RPC endpoint, a wallet-core gate implementation, and an HSM/vault signer. No mainnet or value-transfer path is included in this target.

Run:

```bash
pytest -q bootstrap_wall3t/tests/test_evm_contracts.py
vyper -f abi,bytecode contracts/vyper/BoundaryRegistry.vy
npx --yes solc@0.8.30 --abi --bin -o /tmp/wall3t-solidity-artifacts contracts/evm/BoundaryRegistry.sol
```

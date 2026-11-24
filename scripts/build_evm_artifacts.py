#!/usr/bin/env python3
"""Compile Solidity/Vyper boundary contracts into ignored deployment artifacts.

The output contains ABI, bytecode, compiler identity, and source SHA-256. It
never accepts or writes RPC URLs, private keys, mnemonics, or signed payloads.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOLIDITY = ROOT / "contracts/evm/BoundaryRegistry.sol"
VYPER = ROOT / "contracts/vyper/BoundaryRegistry.vy"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str], *, cwd: Path = ROOT) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/evm")
    args = parser.parse_args()
    output: Path = args.output
    output.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="wall3t-solc-") as temp:
        temp_path = Path(temp)
        run(["npx", "--yes", "solc@0.8.30", "--abi", "--bin", "-o", str(temp_path), str(SOLIDITY)])
        abi_path = next(temp_path.glob("*.abi"))
        bin_path = next(temp_path.glob("*.bin"))
        solidity_payload = {
            "contract": "BoundaryRegistry",
            "language": "solidity",
            "compiler": "solcjs-0.8.30",
            "abi": json.loads(abi_path.read_text()),
            "bytecode": "0x" + bin_path.read_text().strip(),
            "source_sha256": digest(SOLIDITY),
        }
        (output / "solidity-BoundaryRegistry.json").write_text(
            json.dumps(solidity_payload, indent=2, sort_keys=True) + "\n"
        )

    with tempfile.TemporaryDirectory(prefix="wall3t-vyper-") as temp:
        temp_path = Path(temp)
        abi_path = temp_path / "BoundaryRegistry.abi"
        bin_path = temp_path / "BoundaryRegistry.bin"
        with abi_path.open("w") as abi_file:
            subprocess.run(["vyper", "-f", "abi", str(VYPER)], check=True, stdout=abi_file)
        with bin_path.open("w") as bin_file:
            subprocess.run(["vyper", "-f", "bytecode", str(VYPER)], check=True, stdout=bin_file)
        vyper_payload = {
            "contract": "BoundaryRegistry",
            "language": "vyper",
            "compiler": "vyper-0.4.3",
            "abi": json.loads(abi_path.read_text()),
            "bytecode": "0x" + bin_path.read_text().strip().removeprefix("0x"),
            "source_sha256": digest(VYPER),
        }
        (output / "vyper-BoundaryRegistry.json").write_text(
            json.dumps(vyper_payload, indent=2, sort_keys=True) + "\n"
        )

    print(f"Wrote EVM artifacts to {output}")


if __name__ == "__main__":
    main()

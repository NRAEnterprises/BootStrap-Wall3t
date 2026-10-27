# node_manager/manager.py
"""Utility functions for starting, stopping and monitoring blockchain nodes.
Supported node types are expressed via a simple configuration dict. Currently
the implementation uses Docker‑compose services defined in the project's
`docker-compose.yaml` (e.g., `bitcoin`, `lnd`, `geth`).
"""

import subprocess
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

# Path to the project's docker‑compose file (relative to repo root)
COMPOSE_FILE = Path(__file__).parents[2] / "docker-compose.yaml"

# Example node configuration – extend as needed.
DEFAULT_NODES: Dict[str, Dict[str, Any]] = {
    "bitcoin": {
        "service": "bitcoin",
        "description": "Bitcoin Core full node (mainnet)",
        "rpc_url": "http://127.0.0.1:8332",
        "metrics_url": "http://127.0.0.1:9332",
    },
    "lnd": {
        "service": "lnd",
        "description": "Lightning Network Daemon (Neutrino backend)",
        "grpc": "localhost:10009",
    },
    "geth": {
        "service": "geth",
        "description": "Ethereum Go client",
        "rpc_url": "http://127.0.0.1:8545",
    },
}

def _run_compose(args: List[str]) -> subprocess.CompletedProcess:
    """Run a docker‑compose command with the repository's compose file.
    Returns the completed process (stdout, stderr, returncode)."""
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE)] + args
    return subprocess.run(cmd, capture_output=True, text=True)

def start_node(name: str) -> Dict[str, Any]:
    cfg = DEFAULT_NODES.get(name)
    if not cfg:
        return {"error": f"Unknown node '{name}'"}
    result = _run_compose(["up", "-d", cfg["service"]])
    return {
        "service": cfg["service"],
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }

def stop_node(name: str) -> Dict[str, Any]:
    cfg = DEFAULT_NODES.get(name)
    if not cfg:
        return {"error": f"Unknown node '{name}'"}
    result = _run_compose(["stop", cfg["service"]])
    return {
        "service": cfg["service"],
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }

def node_status(name: str) -> Dict[str, Any]:
    cfg = DEFAULT_NODES.get(name)
    if not cfg:
        return {"error": f"Unknown node '{name}'"}
    # Docker‑compose ps gives a quick status snapshot.
    result = _run_compose(["ps", cfg["service"]])
    return {
        "service": cfg["service"],
        "output": result.stdout,
        "returncode": result.returncode,
    }

def list_nodes() -> List[Dict[str, Any]]:
    return [{"id": k, **v} for k, v in DEFAULT_NODES.items()]

def get_node_config(name: str) -> Optional[Dict[str, Any]]:
    return DEFAULT_NODES.get(name)

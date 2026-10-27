#!/usr/bin/env bash
# scripts/run_server.sh
# Starts the minimal FastAPI dev server used by the extension UI.
# Requires the Python virtual environment with FastAPI and uvicorn installed.
# Usage:   ./scripts/run_server.sh
# It will listen on 127.0.0.1:8000 (default in background.js).

set -e

# Activate poetry environment if present
if command -v poetry &>/dev/null; then
  echo "Activating poetry environment..."
  poetry run uvicorn bootstrap_wallet.server.main:app --host 127.0.0.1 --port 8000 --reload
else
  echo "Running uvicorn directly (ensure dependencies are installed)..."
  uvicorn bootstrap_wallet.server.main:app --host 127.0.0.1 --port 8000 --reload
fi

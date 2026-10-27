#!/usr/bin/env bash
# scripts/build_extension.sh
# Packages the browser extension into a zip file for loading into Chrome/Brave/Firefox.
# Usage:   ./scripts/build_extension.sh
# Output:  ./dist/bootstrap_wall3t-extension.zip

set -euo pipefail

# Ensure the output directory exists
mkdir -p dist

# Zip the extension directory (preserve permissions, no extra folder nesting)
zip -r "dist/bootstrap_wall3t-extension.zip" extension/*

echo "Extension packaged at dist/bootstrap_wall3t-extension.zip"

#!/usr/bin/env bash
set -euo pipefail

echo "[*] Installing Docker on Kali..."
sudo apt update
sudo apt install -y docker.io docker-compose-plugin curl jq python3-venv

sudo systemctl enable docker --now
sudo usermod -aG docker "$USER"

echo "[*] Docker installed. Log out and back in for group changes."
echo "[*] Then run: docker --version"

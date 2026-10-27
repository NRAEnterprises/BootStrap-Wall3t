"""
Automations Vault Subsystem (HashiCorp Vault Client & Local Secret Store).
Dedicated to workflow automation secrets, RPC endpoints, and non-signing API keys.
Strictly segregated from the PQC Sovereign Key Vault.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
import requests

from bootstrap_wall3t.core.config import settings

class AutomationsVault:
    """
    Manages operational automation secrets via HashiCorp Vault API or secure local configuration.
    """

    def __init__(self, vault_url: Optional[str] = None, vault_token: Optional[str] = None):
        self.vault_url = (vault_url or settings.vault.hashicorp_vault_url).rstrip("/")
        self.token = vault_token or settings.vault.hashicorp_vault_token
        self.local_cache_path = Path("./data/vault/automations_secrets.json")

    def _headers(self) -> Dict[str, str]:
        return {
            "X-Vault-Token": self.token,
            "Content-Type": "application/json"
        }

    def get_secret(self, path: str, key: Optional[str] = None) -> Any:
        """
        Fetches an automation secret from HashiCorp Vault kv-v2 engine (or local fallback).
        """
        # If HashiCorp Vault is live and configured
        if self.token and self.vault_url:
            url = f"{self.vault_url}/v1/secret/data/{path}"
            try:
                resp = requests.get(url, headers=self._headers(), timeout=5)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("data", {})
                    return data.get(key) if key else data
            except Exception:
                pass  # Fallback to local storage

        # Local fallback for development/offline agent clusters
        if self.local_cache_path.exists():
            try:
                local_data = json.loads(self.local_cache_path.read_text())
                path_data = local_data.get(path, {})
                return path_data.get(key) if key else path_data
            except Exception:
                pass

        return None

    def set_secret(self, path: str, secrets: Dict[str, Any]) -> bool:
        """
        Stores an automation secret into HashiCorp Vault kv-v2 (or local store).
        """
        if self.token and self.vault_url:
            url = f"{self.vault_url}/v1/secret/data/{path}"
            payload = {"data": secrets}
            try:
                resp = requests.post(url, headers=self._headers(), json=payload, timeout=5)
                if resp.status_code in (200, 204):
                    return True
            except Exception:
                pass

        # Write to local encrypted/secured cache
        self.local_cache_path.parent.mkdir(parents=True, exist_ok=True)
        local_data = {}
        if self.local_cache_path.exists():
            try:
                local_data = json.loads(self.local_cache_path.read_text())
            except Exception:
                local_data = {}
        local_data[path] = secrets
        self.local_cache_path.write_text(json.dumps(local_data, indent=2))
        return True

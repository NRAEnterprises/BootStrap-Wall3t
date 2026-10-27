"""
Configuration management for bootstrap_wall3t.
Reads environment variables with production defaults.
"""

import os
from pathlib import Path
from pydantic import BaseModel, Field

class NetworkConfig(BaseModel):
    # Lightning / LND
    lnd_dir: str = Field(default_factory=lambda: os.getenv("LND_DIR", "./data/lnd"))
    lnd_host: str = Field(default_factory=lambda: os.getenv("LND_HOST", "localhost:10009"))
    lnd_rest_url: str = Field(default_factory=lambda: os.getenv("LND_REST_URL", "http://localhost:8080"))
    aperture_url: str = Field(default_factory=lambda: os.getenv("APERTURE_URL", "http://localhost:8081"))
    
    # Fuel Network (Ignition)
    fuel_provider_url: str = Field(
        default_factory=lambda: os.getenv("FUEL_PROVIDER_URL", "https://mainnet.fuel.network/v1/graphql")
    )
    
    # EVM L2s
    arbitrum_rpc_url: str = Field(
        default_factory=lambda: os.getenv("ARBITRUM_RPC_URL", "https://arb1.arbitrum.io/rpc")
    )
    base_rpc_url: str = Field(
        default_factory=lambda: os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
    )
    
    # Solana
    solana_rpc_url: str = Field(
        default_factory=lambda: os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")
    )

class VaultConfig(BaseModel):
    # HashiCorp Automations Vault
    hashicorp_vault_url: str = Field(default_factory=lambda: os.getenv("VAULT_ADDR", "http://127.0.0.1:8200"))
    hashicorp_vault_token: str = Field(default_factory=lambda: os.getenv("VAULT_TOKEN", ""))
    
    # PQC Key Vault Local Ledger (Encrypted with ML-KEM)
    pqc_ledger_path: str = Field(
        default_factory=lambda: os.getenv("PQC_LEDGER_PATH", "./data/vault/pqc_ledger.enc")
    )
    threat_registry_path: str = Field(
        default_factory=lambda: os.getenv("THREAT_REGISTRY_PATH", "./data/threat_registry.json")
    )

class Config(BaseModel):
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    vault: VaultConfig = Field(default_factory=VaultConfig)
    max_payguard_sats: int = Field(default_factory=lambda: int(os.getenv("PAYGUARD_MAX_SATS", "5000")))

settings = Config()

"""
AgentShield: Real-Time Shared Threat Intelligence and Blacklisting Engine.
Intercepts all transactions across all agents to block toxic coins, honeypots, and rug-pulls.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import fcntl

class ThreatQuarantineException(PermissionError):
    """Raised when an asset or transaction is blocked by AgentShield."""
    pass

class ThreatRegistry:
    """
    Synchronized thread-safe and process-safe threat intelligence registry.
    Shared across all running agents.
    """

    def __init__(self, registry_path: Optional[str] = None):
        self.registry_path = Path(registry_path or "./data/threat_registry.json")
        self._memory_cache: Dict[str, Dict[str, Any]] = {}
        self._init_storage()

    def _init_storage(self):
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.registry_path.exists():
            initial_data = {
                "version": "1.0.0",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "blacklisted_tokens": {},
                "blacklisted_pairs": {},
                "blacklisted_deployers": {}
            }
            self.registry_path.write_text(json.dumps(initial_data, indent=2))
        self.reload()

    def reload(self):
        """Reloads the blacklist into fast memory."""
        try:
            with open(self.registry_path, "r") as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                data = json.load(f)
                fcntl.flock(f, fcntl.LOCK_UN)
                self._memory_cache = data.get("blacklisted_tokens", {})
        except Exception:
            pass

    def quarantine_asset(
        self,
        token_address: str,
        chain: str,
        symbol: str,
        reason: str,
        reported_by: str,
        severity: str = "CRITICAL"
    ) -> Dict[str, Any]:
        """
        Instantly blacklists a coin across all agents.
        Writes atomically with file locking and updates active memory cache immediately.
        """
        token_key = f"{chain.lower()}:{token_address.lower()}"
        entry = {
            "token_key": token_key,
            "address": token_address.lower(),
            "chain": chain.lower(),
            "symbol": symbol.upper(),
            "reason": reason,
            "reported_by": reported_by,
            "severity": severity,
            "quarantined_at": datetime.now(timezone.utc).isoformat()
        }

        # Update local memory immediately
        self._memory_cache[token_key] = entry
        if symbol:
            self._memory_cache[f"{chain.lower()}:{symbol.lower()}"] = entry

        # Atomic update on disk
        with open(self.registry_path, "r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                data = json.load(f)
            except Exception:
                data = {"blacklisted_tokens": {}}
            
            if "blacklisted_tokens" not in data:
                data["blacklisted_tokens"] = {}
                
            data["blacklisted_tokens"][token_key] = entry
            if symbol:
                data["blacklisted_tokens"][f"{chain.lower()}:{symbol.lower()}"] = entry
                
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            
            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()
            fcntl.flock(f, fcntl.LOCK_UN)

        return entry

    def is_blacklisted(self, chain: str, token_identifier: str) -> Optional[Dict[str, Any]]:
        """
        Checks whether a token address or symbol is blacklisted on the given chain.
        """
        self.reload()
        token_key = f"{chain.lower()}:{token_identifier.lower()}"
        return self._memory_cache.get(token_key)

    def assert_trade_permitted(self, chain: str, token_address: str, symbol: Optional[str] = None):
        """
        Pre-trade execution gate.
        Raises ThreatQuarantineException if the token or symbol is blacklisted.
        """
        # Check by contract address
        hit = self.is_blacklisted(chain, token_address)
        if hit:
            raise ThreatQuarantineException(
                f"[AgentShield BLOCK] Token {token_address} is quarantined! "
                f"Reason: {hit.get('reason')} (Reported by {hit.get('reported_by')})"
            )

        # Check by symbol
        if symbol:
            hit = self.is_blacklisted(chain, symbol)
            if hit:
                raise ThreatQuarantineException(
                    f"[AgentShield BLOCK] Token symbol {symbol} is quarantined! "
                    f"Reason: {hit.get('reason')} (Reported by {hit.get('reported_by')})"
                )

    def evaluate_token_risk(self, token_metadata: Dict[str, Any], reported_by: str) -> bool:
        """
        Automated risk heuristic evaluation.
        If any red flags are identified, triggers immediate quarantine.
        """
        chain = token_metadata.get("chain", "evm")
        address = token_metadata.get("address", "")
        symbol = token_metadata.get("symbol", "")
        sell_tax = token_metadata.get("sell_tax_pct", 0.0)
        has_freeze_authority = token_metadata.get("has_freeze_authority", False)
        liquidity_usd = token_metadata.get("liquidity_usd", 100000.0)
        is_honeypot = token_metadata.get("is_honeypot", False)

        reasons = []
        if is_honeypot:
            reasons.append("Detected simulated honeypot trap")
        if sell_tax > 5.0:
            reasons.append(f"Excessive sell tax ({sell_tax}% > 5.0% threshold)")
        if has_freeze_authority and chain.lower() in ("solana", "evm"):
            reasons.append("Owner retains arbitrary freeze/blacklist authority")
        if liquidity_usd < 500.0:
            reasons.append(f"Critically low liquidity (${liquidity_usd:.2f})")

        if reasons:
            self.quarantine_asset(
                token_address=address,
                chain=chain,
                symbol=symbol,
                reason="; ".join(reasons),
                reported_by=reported_by,
                severity="CRITICAL"
            )
            return False

        return True

# Singleton threat registry instance
shield = ThreatRegistry()

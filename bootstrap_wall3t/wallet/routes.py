"""
Systematic Transport and Routing Optimization Matrix.
Maps the cheapest transport corridors, Fuel Network advantages, Lightning channels,
cross-chain bridges, and premier staking protocols across all chains.
"""

from dataclasses import dataclass
from typing import Dict, Any, List, Optional

@dataclass
class TransportHop:
    chain: str
    protocol: str
    action: str
    estimated_fee_usd: float
    latency_seconds: int
    rationale: str

@dataclass
class RoutePlan:
    source_chain: str
    dest_chain: str
    asset: str
    amount_usd: float
    total_estimated_fee_usd: float
    total_latency_seconds: int
    hops: List[TransportHop]
    guideline: str

class RoutingMatrix:
    """
    Determines mathematically optimal transport corridors and staking destinations.
    """

    # Fuel Network and Lightning Network baseline metrics
    NETWORK_PROFILES = {
        "lightning": {
            "name": "Bitcoin Lightning Network",
            "base_fee_usd": 0.0001,
            "speed": "instant",
            "gas_volatility": "zero",
            "recommended_max_usd": 50000.0,
            "protocols": ["LND", "PhoenixD", "Aperture", "Boltz"]
        },
        "fuel": {
            "name": "Fuel Network (Ignition)",
            "base_fee_usd": 0.001,
            "speed": "< 1 second",
            "gas_volatility": "ultra-low (parallel UTXO execution avoids EVM contention)",
            "recommended_max_usd": 1000000.0,
            "protocols": ["Mira DEX", "SwayLend", "Fuel Bridge"]
        },
        "arbitrum": {
            "name": "Arbitrum One (L2)",
            "base_fee_usd": 0.02,
            "speed": "2 seconds",
            "gas_volatility": "low-medium",
            "protocols": ["Uniswap v3", "Camelot", "Aave v3", "Across"]
        },
        "base": {
            "name": "Base (Coinbase L2)",
            "base_fee_usd": 0.01,
            "speed": "2 seconds",
            "gas_volatility": "low",
            "protocols": ["Aerodrome", "Uniswap v3", "Aave v3", "Across"]
        },
        "solana": {
            "name": "Solana",
            "base_fee_usd": 0.0005,
            "speed": "400 ms",
            "gas_volatility": "low",
            "protocols": ["Jupiter", "Raydium", "Jito", "Marinade"]
        },
        "bitcoin_l1": {
            "name": "Bitcoin Mainnet L1",
            "base_fee_usd": 4.50,
            "speed": "10 - 60 minutes",
            "gas_volatility": "extreme",
            "avoid_for_amounts_below_usd": 10000.0
        }
    }

    # Premier Staking and Yield Protocols
    STAKING_REGISTRY = {
        "BTC": [
            {
                "protocol": "Babylon Protocol",
                "type": "Trustless Native BTC Staking (PoS Security)",
                "expected_apy": "3.5% - 7.0%",
                "risk_rating": "A+",
                "notes": "Cryptographic self-custody on Bitcoin L1 without wrapping or bridging."
            },
            {
                "protocol": "LND Routing Node Liquidity",
                "type": "Lightning Routing Fee Capture",
                "expected_apy": "2.0% - 6.0%",
                "risk_rating": "A",
                "notes": "Provide bidirectional inbound/outbound channel liquidity to capture routing fees."
            },
            {
                "protocol": "CoreDAO BTC Staking",
                "type": "Non-custodial Time-lock Staking",
                "expected_apy": "4.0% - 8.0%",
                "risk_rating": "A-",
                "notes": "Locks BTC in native Bitcoin script while earning CORE rewards."
            }
        ],
        "ETH": [
            {
                "protocol": "Lido Finance (stETH)",
                "type": "Liquid Staking",
                "expected_apy": "3.2% - 3.8%",
                "risk_rating": "AAA",
                "notes": "Most liquid EVM liquid staking token. Supported across all L2 money markets."
            },
            {
                "protocol": "Rocket Pool (rETH)",
                "type": "Decentralized Liquid Staking",
                "expected_apy": "3.0% - 3.6%",
                "risk_rating": "AAA",
                "notes": "Permissionless node operator set, minimal governance risk."
            },
            {
                "protocol": "Aave v3 (Arbitrum/Base)",
                "type": "Lending Market Yield",
                "expected_apy": "2.5% - 6.0%",
                "risk_rating": "AAA",
                "notes": "Supply ETH collateral to earn base yield + borrower interest with sub-$0.05 deposit cost."
            }
        ],
        "FUEL": [
            {
                "protocol": "Mira DEX Liquidity Pools",
                "type": "Automated Market Maker LP",
                "expected_apy": "12.0% - 28.0%",
                "risk_rating": "B+",
                "notes": "Parallel execution UTXO AMM on Fuel Ignition. Near-zero gas fees maximize LP compounding."
            },
            {
                "protocol": "SwayLend",
                "type": "Decentralized Lending & Borrowing",
                "expected_apy": "5.0% - 15.0%",
                "risk_rating": "B+",
                "notes": "Native Fuel money market. High capital efficiency due to FuelVM state architecture."
            }
        ],
        "SOL": [
            {
                "protocol": "Jito (JitoSOL)",
                "type": "MEV-Boosted Liquid Staking",
                "expected_apy": "7.2% - 8.5%",
                "risk_rating": "A+",
                "notes": "Captures both standard validator inflation rewards and MEV block tips."
            },
            {
                "protocol": "Marinade Finance (mSOL)",
                "type": "Algorithmic Liquid Staking",
                "expected_apy": "6.8% - 7.5%",
                "risk_rating": "A",
                "notes": "Delegates across 100+ high-performing decentralized validators."
            }
        ]
    }

    def plan_route(self, source_chain: str, dest_chain: str, asset: str, amount_usd: float) -> RoutePlan:
        """
        Formulates the most cost-effective and secure route between chains and assets.
        Enforces Fuel for EVM execution and Lightning for BTC movement.
        """
        src = source_chain.lower()
        dst = dest_chain.lower()
        hops: List[TransportHop] = []
        guideline = ""

        # Case 1: Bitcoin Transfer
        if asset.upper() == "BTC":
            if src in ("lightning", "lnd", "phoenixd") and dst in ("lightning", "lnd", "phoenixd"):
                hops.append(TransportHop(
                    chain="lightning",
                    protocol="LND / BOLT11",
                    action="Instant payment invoice routing",
                    estimated_fee_usd=0.0001,
                    latency_seconds=1,
                    rationale="Lightning is native, zero-friction, and eliminates Bitcoin L1 mempool fees."
                ))
                guideline = "USE LIGHTNING DIRECT: Bypass Bitcoin L1 completely."

            elif src in ("lightning", "lnd") and dst in ("arbitrum", "base", "ethereum", "liquid"):
                hops.append(TransportHop(
                    chain="lightning",
                    protocol="Boltz Submarine Swap",
                    action="Atomic swap Lightning BTC -> Arbitrum USDC / WBTC",
                    estimated_fee_usd=0.85,
                    latency_seconds=30,
                    rationale="Boltz provides trustless HTLC cross-chain swaps without touching Bitcoin L1 mempool."
                ))
                guideline = "USE BOLTZ SUBMARINE SWAP: Avoids expensive L1 bridging."

            else:
                hops.append(TransportHop(
                    chain="lightning",
                    protocol="LND / Neutrino",
                    action="Off-chain routing",
                    estimated_fee_usd=0.001,
                    latency_seconds=2,
                    rationale="Routing through Lightning preserves capital."
                ))
                guideline = "MANDATORY: Never use Bitcoin L1 for transactions under 0.5 BTC."

        # Case 2: EVM / DeFi Execution
        elif asset.upper() in ("USDC", "USDT", "ETH", "STABLE"):
            # If executing frequent micro-swaps or high-frequency tasks: route through Fuel
            if dst in ("fuel", "fuel_network") or (src != "fuel" and amount_usd < 500):
                hops.append(TransportHop(
                    chain="fuel",
                    protocol="Fuel Ignition (FuelVM)",
                    action="Parallel UTXO execution and swap",
                    estimated_fee_usd=0.001,
                    latency_seconds=1,
                    rationale="Fuel offers non-fluctuating sub-cent gas fees and parallel execution to prevent fee drain."
                ))
                guideline = "ROUTE VIA FUEL NETWORK: Parallel UTXO state prevents EVM gas volatility."

            elif src in ("arbitrum", "base") and dst in ("arbitrum", "base"):
                hops.append(TransportHop(
                    chain=src,
                    protocol="Across Protocol",
                    action="Intents-based L2 bridge",
                    estimated_fee_usd=0.05,
                    latency_seconds=10,
                    rationale="Across Protocol uses intent solvers to deliver the lowest fee bridge between L2s."
                ))
                guideline = "USE ACROSS PROTOCOL: Minimal slippage and sub-minute settlement."

            else:
                hops.append(TransportHop(
                    chain=src,
                    protocol="Base / Arbitrum L2",
                    action="Standard low-fee L2 execution",
                    estimated_fee_usd=0.02,
                    latency_seconds=3,
                    rationale="Avoid Ethereum L1 mainnet. Keep operations inside low-fee rollups."
                ))
                guideline = "STRICT L2 ENFORCEMENT: Never broadcast on Ethereum mainnet L1."

        # Case 3: Solana
        elif asset.upper() in ("SOL", "SPL"):
            hops.append(TransportHop(
                chain="solana",
                protocol="Jupiter Aggregator",
                action="Best route DEX aggregation",
                estimated_fee_usd=0.0005,
                latency_seconds=1,
                rationale="Jupiter splits routes across Raydium, Orca, and Phoenix for lowest price impact."
            ))
            guideline = "USE JUPITER ON SOLANA: Sub-cent execution and automated slippage controls."

        total_fee = sum(h.estimated_fee_usd for h in hops)
        total_latency = sum(h.latency_seconds for h in hops)

        return RoutePlan(
            source_chain=source_chain,
            dest_chain=dest_chain,
            asset=asset,
            amount_usd=amount_usd,
            total_estimated_fee_usd=total_fee,
            total_latency_seconds=total_latency,
            hops=hops,
            guideline=guideline
        )

    def get_staking_destinations(self, asset: str) -> List[Dict[str, Any]]:
        """Returns premier staking protocols filtered by asset."""
        return self.STAKING_REGISTRY.get(asset.upper(), [])

routes = RoutingMatrix()

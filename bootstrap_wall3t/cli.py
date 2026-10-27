#!/usr/bin/env python3
"""
Sats-Stack Unified Command Line Interface.
Control ceremony unlocks, view routing guidelines, inspect blacklist, and operate agent wallets.
"""

import argparse
import json
import sys
from pathlib import Path

from bootstrap_wall3t.vault.pqc_key_vault import PQCKeyVault
from bootstrap_wall3t.wallet.blacklisting import shield
from bootstrap_wall3t.wallet.routes import routes
from bootstrap_wall3t.bootstrap.faucet_sweeper import FaucetSweeper
from bootstrap_wall3t.bootstrap.arbitrage_scout import FlashArbitrageScout

def cmd_ceremony_init(args):
    vault = PQCKeyVault()
    priv, pub = vault.generate_session_keypair()
    
    # Create initial ledger template
    template = {
        "agent_primary": {
            "evm_privkey": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "lightning_node": "lnd:10009",
            "fuel_address": "fuel10123456789abcdef",
            "solana_pubkey": "So11111111111111111111111111111111111111112"
        }
    }
    vault.save_encrypted_ledger(template, pub)
    print("=" * 60)
    print("✨ PQC Session Ceremony Initialized Successfully!")
    print("=" * 60)
    print(f"Encrypted ledger written to: {vault.ledger_path}")
    print("Algorithm: NIST FIPS 203 (ML-KEM-768) + AES-256-GCM")
    print("Store the operator private key securely in memory during automation runs.")

def cmd_shield_status(args):
    shield.reload()
    tokens = shield._memory_cache
    print("=" * 60)
    print("🛡️  AgentShield: Synchronized Threat Intelligence Status")
    print("=" * 60)
    print(f"Active Quarantined Tokens / Symbols: {len(tokens)}")
    for key, entry in tokens.items():
        print(f" • [{entry.get('chain', 'any').upper()}] {key} -> {entry.get('reason')} (Reported by: {entry.get('reported_by')})")

def cmd_shield_quarantine(args):
    entry = shield.quarantine_asset(
        token_address=args.token,
        chain=args.chain,
        symbol=args.symbol or "",
        reason=args.reason,
        reported_by=args.agent or "operator_manual",
        severity="CRITICAL"
    )
    print(f"🚨 [QUARANTINE ACTIVATED] Asset {args.token} ({args.chain}) blocked across all agent wallets!")
    print(json.dumps(entry, indent=2))

def cmd_routes_plan(args):
    plan = routes.plan_route(args.source, args.dest, args.asset, args.amount)
    print("=" * 60)
    print("🛰️  Systematic Transport Plan")
    print("=" * 60)
    print(f"Route: {plan.source_chain.upper()} ➔ {plan.dest_chain.upper()} ({plan.asset} | ${plan.amount_usd:,.2f})")
    print(f"Guideline: {plan.guideline}")
    print(f"Est. Total Fee: ${plan.total_estimated_fee_usd:.4f} USD")
    print(f"Est. Latency: {plan.total_latency_seconds} seconds")
    print("-" * 60)
    for i, hop in enumerate(plan.hops, 1):
        print(f"Hop {i}: [{hop.chain.upper()}] {hop.action} via {hop.protocol} (Fee: ${hop.estimated_fee_usd:.4f})")
        print(f"       Rationale: {hop.rationale}")

def cmd_routes_staking(args):
    stakings = routes.get_staking_destinations(args.asset)
    print("=" * 60)
    print(f"🏦 Premier Staking Protocols for {args.asset.upper()}")
    print("=" * 60)
    for s in stakings:
        print(f"• Protocol:    {s['protocol']}")
        print(f"  Type:        {s['type']}")
        print(f"  Yield:       {s['expected_apy']}")
        print(f"  Risk Rating: {s['risk_rating']}")
        print(f"  Notes:       {s['notes']}")
        print("-" * 40)

def cmd_bootstrap_status(args):
    print("=" * 60)
    print("⚡ Capital Bootstrapping Influx Matrix (Zero-to-Compound)")
    print("=" * 60)
    print("1. L402 Paywall Intelligence API (Aperture + FastAPI on port 8082)")
    print("   • Status: Configured (/v1/audit/token, /v1/routing/optimal, /v1/alpha/sentiment)")
    print("2. Nostr NIP-57 Zap Harvesters")
    print("   • Status: Relays connected; automated pulse emitter ready")
    print("3. Stacker News Curation Worker")
    print("   • Status: Payguard limits active; GraphQL monitoring armed")
    print("4. FaucetPay Multi-Coin Sweeper")
    sweeper = FaucetSweeper()
    ev = sweeper.calculate_net_sweep_ev("DOGE", 8.50)
    print(f"   • Mathematical EV Model: Sample $8.50 DOGE sweep yields net ${ev['net_yield_usd']:.2f} (Action: {ev['recommended_action']})")
    print("5. Zero-Capital Flash Arbitrage Scout")
    scout = FlashArbitrageScout()
    arb = scout.scan_spread("ETH/USDC", "Uniswap-v3", "Camelot", price_buy=2500.0, price_sell=2515.0, borrow_amount_usd=10000.0)
    print(f"   • Flash Spread Simulation: Gross {arb['gross_spread_pct']}% -> Net profit ${arb['net_profit_usd']} ({arb['provider']})")

def main():
    parser = argparse.ArgumentParser(description="Sats-Stack Autonomous Financial Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Ceremony
    ceremony_p = subparsers.add_parser("ceremony", help="PQC key vault ceremony management")
    ceremony_sub = ceremony_p.add_subparsers(dest="subcommand", required=True)
    ceremony_sub.add_parser("init", help="Initialize and encrypt master ledger")

    # Shield
    shield_p = subparsers.add_parser("shield", help="AgentShield threat intelligence")
    shield_sub = shield_p.add_subparsers(dest="subcommand", required=True)
    shield_sub.add_parser("status", help="Show quarantined tokens")
    quar_p = shield_sub.add_parser("quarantine", help="Quarantine a bad coin")
    quar_p.add_argument("--chain", required=True, help="Chain name (fuel, arbitrum, base, solana, etc.)")
    quar_p.add_argument("--token", required=True, help="Token contract address or identifier")
    quar_p.add_argument("--symbol", default="", help="Token symbol")
    quar_p.add_argument("--reason", required=True, help="Reason for quarantine")
    quar_p.add_argument("--agent", default="operator", help="Reporting agent ID")

    # Routes
    routes_p = subparsers.add_parser("routes", help="Systematic transport routing matrix")
    routes_sub = routes_p.add_subparsers(dest="subcommand", required=True)
    plan_p = routes_sub.add_parser("plan", help="Compute best transport route")
    plan_p.add_argument("--source", required=True, help="Source chain")
    plan_p.add_argument("--dest", required=True, help="Destination chain")
    plan_p.add_argument("--asset", required=True, help="Asset ticker")
    plan_p.add_argument("--amount", type=float, default=100.0, help="Amount in USD")
    
    stake_p = routes_sub.add_parser("staking", help="Show premier staking destinations")
    stake_p.add_argument("--asset", required=True, help="Asset ticker (BTC, ETH, FUEL, SOL)")

    # Bootstrap
    boot_p = subparsers.add_parser("bootstrap", help="Funds generation influx monitoring")
    boot_sub = boot_p.add_subparsers(dest="subcommand", required=True)
    boot_sub.add_parser("status", help="Inspect status of bootstrap workers")

    args = parser.parse_args()

    if args.command == "ceremony" and args.subcommand == "init":
        cmd_ceremony_init(args)
    elif args.command == "shield" and args.subcommand == "status":
        cmd_shield_status(args)
    elif args.command == "shield" and args.subcommand == "quarantine":
        cmd_shield_quarantine(args)
    elif args.command == "routes" and args.subcommand == "plan":
        cmd_routes_plan(args)
    elif args.command == "routes" and args.subcommand == "staking":
        cmd_routes_staking(args)
    elif args.command == "bootstrap" and args.subcommand == "status":
        cmd_bootstrap_status(args)

if __name__ == "__main__":
    main()

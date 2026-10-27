# Sats-Stack: Autonomous Agent Multi-Chain Financial Architecture

Production-grade autonomous agent financial stack and universal high-security wallet engine, designed for capital bootstrapping from zero to multi-chain yield and algorithmic trading.

## Architectural Highlights

* **Post-Quantum Dual-Vault Security Tier**:
  * **Automations Vault (HashiCorp Vault)**: Isolates non-signing operational secrets (Stacker News, Nostr, FaucetPay tokens, RPCs).
  * **PQC Key Vault (NIST FIPS 203 & 204)**: Encrypted with **ML-KEM-768** hybrid envelope encryption and authorized via **ML-DSA-65** post-quantum signatures.
  * **Ephemeral In-Memory Enclave**: Unlocked once per session via a rotating operator public key ceremony. Keys reside strictly in RAM (pinned with POSIX `mlock`) and are zeroized upon process termination (`atexit`, signal traps). Zero keys touch persistent storage.
* **AgentShield Shared Threat Intelligence**:
  * Real-time synchronized blacklist blocking honeypots, rug pulls, freeze traps, and high-tax (>5%) tokens.
  * Synchronously intercepts all transactions before signing. When any agent detects an anomaly, it triggers an instant quarantine across all agent wallets simultaneously.
* **Systematic Transport & Routing Matrix**:
  * **Bitcoin Movements**: Enforces **Lightning Network** direct routing (LND/PhoenixD) and **Boltz Submarine Swaps** to eliminate Bitcoin L1 mempool fees.
  * **EVM & High-Frequency Swaps**: Prioritizes **Fuel Network (Ignition)** for predictable sub-cent gas fees via parallel UTXO execution, avoiding EVM state contention spikes.
  * **Cross-Chain Bridges**: Across Protocol and Stargate for minimal slippage.
  * **Premier Staking**: Babylon Protocol (BTC), Mira DEX / SwayLend (Fuel), JitoSOL (Solana), Lido / Aave v3 (EVM).
* **Capital Bootstrapping Influx (Zero-to-Compound)**:
  * **L402 Paywall Intelligence API**: Sells specialized agent analytics over Lightning via Aperture + FastAPI (HTTP 402).
  * **Nostr NIP-57 Zap Harvesters**: Autonomous market pulse publishing with LNURL-pay metadata.
  * **Stacker News Curation**: Automated high-value replies governed by PayGuard caps.
  * **FaucetPay EV Sweeper**: Mathematical expected value threshold withdrawals.
  * **Atomic Flash Arbitrage**: Zero-capital cross-DEX loops (reverts with 0 loss if execution slips).

---

## Directory Structure

```text
bootstrap_wall3t/
├── docs/
│   └── HARDENED_PLAN.md             # Full architectural blueprint & specification
├── bootstrap_wall3t/
│   ├── vault/
│   │   ├── pqc_key_vault.py         # NIST FIPS 203 ML‑KEM & FIPS 204 ML‑DSA Enclave
│   │   └── automations_vault.py     # HashiCorp Vault client & secret store
│   ├── wallet/
│   │   ├── agent_wallet.py          # Universal Multi‑Chain Agent Wallet
│   │   ├── blacklisting.py          # AgentShield Synchronized Threat Registry
│   │   └── routes.py                # Systematic Transport & Staking Matrix
│   ├── bootstrap/
│   │   ├── l402_monetization.py     # L402 HTTP 402 FastAPI Intelligence Engine
│   │   ├── nostr_zaps.py            # Nostr NIP‑57 Zap Harvester
│   │   ├── stacker_news.py          # Stacker News Curation Worker
│   │   ├── faucet_sweeper.py        # FaucetPay EV‑Positive Sweeper
│   │   └── arbitrage_scout.py       # Zero‑Capital Flash Loan Scout
│   ├── core/
│   │   ├── security.py              # Memory locking (mlock) & zero‑ization
│   │   └── config.py                # Settings and network profiles
│   ├── tests/                       # Unit test suite
│   └── cli.py                       # Unified CLI tool
├── extension/                       # Browser‑extension source (Chrome/Firefox/Brave)
│   ├── manifest.json                # Manifest v3 (compatible with Chrome, Edge, Brave Nightly)
│   ├── background/background.js
│   ├── popup/popup.html
│   ├── popup/popup.js
│   ├── dashboard/index.html
│   ├── dashboard/dashboard.js
│   └── icons/*                     # Placeholder icons (replace with real assets)
├── bootstrap_wallet/server/main.py # FastAPI dev server exposing /vault, /history, /automations
├── bootstrap_wallet/agents/faucet_scraper.py # Simple placeholder agent (scheduled via cron)
├── config/cron.schedule            # Cron jobs for agents & health checks
├── docker-compose.yaml              # LND + Aperture container definitions
├── scripts/
│   ├── run_server.sh                # Starts FastAPI dev server
│   └── build_extension.sh           # Packages the extension into a zip for loading
├── pyproject.toml                   # Python module distribution definition
└── .github/workflows/ci.yml         # CI pipeline (tests, lint, packaging)
```

### Browser support note
*The extension is built using Manifest V3, which is supported by Chrome, Chromium‑based browsers (including **Brave Nightly**), and Firefox (via the manifest‑v3 compatibility layer).*

```
bootstrap_wall3t/
├── docs/
│   └── HARDENED_PLAN.md             # Full architectural blueprint & specification
├── bootstrap_wall3t/
│   ├── vault/
│   │   ├── pqc_key_vault.py         # NIST FIPS 203 ML-KEM & FIPS 204 ML-DSA Enclave
│   │   └── automations_vault.py     # HashiCorp Vault client & secret store
│   ├── wallet/
│   │   ├── agent_wallet.py          # Universal Multi-Chain Agent Wallet
│   │   ├── blacklisting.py          # AgentShield Synchronized Threat Registry
│   │   └── routes.py                # Systematic Transport & Staking Matrix
│   ├── bootstrap/
│   │   ├── l402_monetization.py     # L402 HTTP 402 FastAPI Intelligence Engine
│   │   ├── nostr_zaps.py            # Nostr NIP-57 Zap Harvester
│   │   ├── stacker_news.py          # Stacker News Curation Worker
│   │   ├── faucet_sweeper.py        # FaucetPay EV-Positive Sweeper
│   │   └── arbitrage_scout.py       # Zero-Capital Flash Loan Scout
│   ├── core/
│   │   ├── security.py              # Memory locking (mlock) & zeroization
│   │   └── config.py                # Settings and network profiles
│   ├── tests/                       # Unit test suite
│   └── cli.py                       # Unified CLI tool
├── docker-compose.yaml              # LND + Aperture container definitions
└── pyproject.toml                   # Python module distribution definition
```

---

## CLI Usage

The package exposes the `bootstrap_wall3t` command:

```bash
# 1. Initialize PQC Key Vault ceremony with rotating session key
bootstrap_wall3t ceremony init

# 2. Inspect AgentShield threat registry
bootstrap_wall3t shield status

# 3. Quarantine a suspicious coin across all agents
bootstrap_wall3t shield quarantine --chain fuel --token 0xBAD123 --reason "Detected 15% sell tax"

# 4. Compute optimal transport route (Fuel / Lightning prioritization)
bootstrap_wall3t routes plan --source arbitrum --dest fuel --asset USDC --amount 100
bootstrap_wall3t routes plan --source lnd --dest lnd --asset BTC --amount 50

# 5. Inspect premier staking protocols
bootstrap_wall3t routes staking --asset BTC
bootstrap_wall3t routes staking --asset FUEL

# 6. Check bootstrap worker status
bootstrap_wall3t bootstrap status
```

---

## Running Tests

```bash
python3 -m unittest discover -s bootstrap_wall3t/tests
```

## Node Manager

The **Node Manager** lets you start, stop, and monitor blockchain node services (Bitcoin Core, LND, Geth, etc.) defined in `docker-compose.yaml`.

- **API endpoints** (served by the FastAPI dev server):
  - `GET   /nodes` – list available nodes.
  - `POST  /nodes/{name}/start` – bring a node up (`docker compose up -d`).
  - `POST  /nodes/{name}/stop`  – halt a node (`docker compose stop`).
  - `GET   /nodes/{name}/status` – quick status via `docker compose ps`.
- **Browser extension UI**: open the *Node Manager* page from the popup (link added) or navigate to `extension/nodes/index.html`. The page shows a table of nodes, their description, current status, and Start/Stop buttons.
- **Background script messages**: the extension background now forwards `GET_NODES`, `START_NODE`, `STOP_NODE`, and `NODE_STATUS` messages to the FastAPI server.
- **Security**: endpoints are protected by the placeholder JWT (`Authorization: Bearer dev-token`). Replace with real auth in production.

### Quick test
```bash
# start the dev server (requires poetry or uvicorn installed)
./scripts/run_server.sh &
# then open the extension UI and click the "Node Manager" link.
```

When Docker is installed and `docker-compose.yaml` contains services named `bitcoin`, `lnd`, and `geth`, the UI will report their status and allow you to start/stop them.

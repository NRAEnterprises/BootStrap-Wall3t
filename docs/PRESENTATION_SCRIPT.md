# BootStrap Wall3t — Three-Vault and Global Quarantine Presentation Script

**Format:** speaker script / presentation notes
**Audience:** technical, security, and product reviewers
**Purpose:** explain how full autonomous agent execution coexists with strict custody boundaries and a global automatic blacklist

## Opening — The operating model

BootStrap Wall3t is an automation wallet first. The user does not approve every transaction and does not sit in front of the system supervising ordinary execution.

The user creates or links wallets, funds agent wallets, installs policies and strategy documents, and chooses what authority each agent receives. After that, agents operate autonomously inside their own funded-wallet boundaries.

The parent wallet is the funding and supervisory authority. An agent can use the funds it has been given, but it cannot pull from, borrow from, or derive authority from the parent wallet. The user has visibility into the agent wallets and retains the ability to configure, fund, pause, revoke, or replace authority.

The architecture is built around three vaults and one global quarantine system.

## Section 1 — Structural overview

The system has four important planes.

First is the user and extension plane. This is where the user creates wallets, funds agents, installs policies, reviews activity, and observes results. It is not a key store and it is not a transaction approval queue.

Second is the automation plane. Elixir supervises agent processes, schedules loops, executes workflows, handles retries, runs discovery, and loads approved automation documents.

Third is the wallet trust plane. Rust receives typed intents, resolves chain context, checks policy and quarantine state, constructs and signs transactions, and submits them through validated chain adapters.

Fourth is the custody plane. The three vaults separate credentials and signing material, automation documents, and long-term financial assets.

The key rule is that the automation plane can request actions, but only the wallet trust plane can decide whether an action is executable.

## Section 2 — The Secrets Vault

The Secrets Vault contains material that can authenticate, sign, unlock, or impersonate something.

That includes user and agent private keys, seed phrases, mnemonics, API keys, OAuth tokens, SSH keys, certificates, webhook secrets, signing keys, and authentication credentials.

The vault does not expose these values to the browser extension, to ordinary agent processes, or to the Elixir orchestrator. The Rust wallet boundary receives an opaque signing capability or invokes a vault-backed operation without releasing raw key material.

This separation is important because an automation agent may need to use a signer, but it does not need to know the private key. The agent requests an operation. The wallet core validates the operation, applies policy and quarantine checks, and then performs the protected signing action.

The Secrets Vault is therefore a credential boundary, not an automation database.

## Section 3 — The Automations Vault

The Automations Vault contains the documents and configuration that tell agents what to do.

It stores policies, policy versions, strategy capsules, document packages, automation loops, schedules, triggers, retry behavior, workflow definitions, discovery rules, prompts, templates, operating modes, and circuit-breaker configuration.

These documents are executable instructions only after they are associated with a specific wallet, agent, scope, and version. Every executable strategy or policy must identify its version and content hash so that the wallet can determine exactly what the user authorized.

The Automations Vault cannot sign, unlock the parent wallet, or grant access to the cold financial vault. A document can request an action, but it cannot bypass Rust policy evaluation or the global quarantine system.

This makes autonomous operation practical without turning configuration storage into a source of unrestricted financial authority.

## Section 4 — The Financial Cold Vault

The Financial Cold Vault is for assets the user intends to keep outside the automation float.

It is user-wallet-side custody, not agent custody. It may hold long-term crypto, supported fiat or fiat claims, and semi-flexible staking positions. Keys are generated and held through hardware-backed custody and user-controlled authorization.

Agents cannot access the cold vault, initiate withdrawals, accelerate a delay, cancel a withdrawal, or redirect its destination. They may see only the balance or public position data that the user chooses to expose through the supervisory mirror.

Moving value out of cold storage requires a hardware-backed user authorization, destination verification, an adjustable time delay, a cancellation window, and an immutable audit record.

The delay applies whether the destination is a user hot wallet, an agent wallet, a bank, or another approved external destination.

The purpose of this vault is not to supervise agent trading. Agents can be fully autonomous with money already placed in their own wallets. The cold vault simply remains outside their authority.

## Section 5 — Agent wallet autonomy

An agent wallet is an autonomous operating environment funded by the user.

The user attaches a policy, strategy, document set, and operating configuration. The agent can then trade, rebalance, transfer, bootstrap funds, run discovery-triggered actions, and retry scheduled workflows without a transaction-by-transaction approval prompt.

The user-authored policy defines the operating envelope. Any limits are selected by the user; they are not a platform-imposed requirement to approve ordinary transactions.

The non-negotiable boundary is that autonomy applies to funds already held by the agent wallet. The agent cannot extend its reach into the parent wallet or Financial Cold Vault.

## Section 6 — Global automatic quarantine

The global blacklist is a shared deny system covering the user wallet and every linked agent wallet.

If an agent or the user discovers a bad coin, token, contract, deployer, pair, provider, or strategy family, the discovering wallet submits a quarantine report. No agent-to-agent conversation or approval is required.

The quarantine service creates a new versioned deny state. Linked wallets receive the deny state through the authoritative registry and invalidate positive caches. Every wallet-core write path checks the current quarantine version before it can proceed.

Only the user can reverse a quarantine. Agents can report and activate a quarantine, but they cannot delete it, weaken it, expire it, or override it.

A reversal requires user authorization, and where configured hardware-backed authorization, evidence review, a new registry version, and an audit event. Reversal does not silently restore old allow decisions.

## Section 7 — What the quarantine check covers

The check is not limited to swaps.

For native transfers it checks the chain, destination, and relevant policy scopes.

For token transfers it checks the token, recipient, deployer where known, and destination contract.

For approvals and permits it checks the token, spender, operator, typed-data domain, and chain.

For swaps it checks both assets, routers, pools, callbacks, dependencies, and deployers.

For bridges it checks source and destination assets, bridge contracts, relayers, and destination contracts.

For staking it checks the staking contract, token, validator or operator, and reward contracts.

For agent-to-agent transfers it checks the destination agent wallet, asset, chain, and any receiving contract.

For Lightning it checks the invoice context, destination, provider, and payment scope before sending.

For bootstrap and discovery workflows it checks every generated intent before signing or sending. A discovery worker or bootstrap worker never gets a bypass path.

For strategy activation it checks the strategy capsule, referenced chains, assets, venues, and contracts, then checks every action produced by the strategy.

## Section 8 — The check sequence

The wallet core creates an intent footprint containing every relevant entity: chains, assets, contracts, spenders, venues, providers, operators, and destinations.

The QuarantineGuard evaluates that footprint against the current registry version.

The sequence is:

1. A workflow or agent submits a typed intent.
2. The wallet core derives the complete intent footprint.
3. The current quarantine state is loaded and verified.
4. A stale, unavailable, or unverifiable registry fails closed for affected writes.
5. The action is simulated and the result is checked against the current state.
6. Quarantine is checked again immediately before signing.
7. The transaction is signed only if the deny state is still valid.
8. The broadcast path performs the final check where the chain adapter supports it.
9. The receipt and registry version are written to the audit trail.

This prevents an agent from acting on an old positive decision after another wallet has quarantined the asset.

## Section 9 — Why agents do not need to communicate

Agent-to-agent discussion is not the enforcement mechanism.

The enforcement mechanism is a shared authoritative deny state with versioning and fail-closed reads. A reporting agent submits a quarantine event once. The wallet-core guard in every linked wallet consumes the resulting deny state.

This means an agent does not need to notify every other agent directly, and a compromised or offline agent cannot negotiate around the blacklist.

The quarantine is enforced at the signing boundary, below the workflow layer. That makes it apply to future agent types and new automation templates automatically, provided they submit typed intents through the wallet core.

## Section 10 — What is implemented versus planned

The architecture and acceptance contract are now defined, but the current repository still contains a Python prototype rather than the finalized implementation.

The existing prototype has a local file-backed threat registry and a swap-focused check. It does not yet provide the versioned authoritative registry, user-only reversal, three separate vault principals, Rust wallet-core enforcement, or complete operation coverage described here.

Therefore, the next engineering milestone is not to add more strategy integrations. It is to implement the wallet graph, three-vault access matrix, QuarantineRegistry, QuarantineGuard, and the operation coverage tests.

## Closing

BootStrap Wall3t combines full autonomous execution with strict custody separation.

The user authorizes agents by funding their wallets and assigning policies. The agents can operate independently without emotional or per-transaction interference. The parent wallet remains outside their reach, the cold financial vault remains user-controlled, and the global quarantine system automatically blocks a discovered bad asset across the entire linked wallet group.

That is the core structure: autonomous agents, separated custody, one-way supervision, and a user-controlled global deny switch.

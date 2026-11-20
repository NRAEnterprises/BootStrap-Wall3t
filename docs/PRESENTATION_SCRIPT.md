# BootStrap Wall3t — Detailed Ten-Slide Presentation Script

**Deck:** `BootStrap Wall3t — Three Vaults & Global Quarantine`
**Audience:** technical, security, product, and implementation reviewers
**Review date:** 2026-11-20
**Purpose:** explain the full-autonomy operating model, three-vault architecture, global quarantine invariant, Rust implementation draft, production registry target, and hardware-authorized reversal protocol.

This script is deliberately aligned to the ten slides in the deck. Speaker notes are also attached to the Slides resource; this document is the durable version-control artifact for the narrative.

## Slide 1 — BootStrap Wall3t: three vaults, one global deny state

**Core message:** BootStrap Wall3t is an automation wallet with separated custody and an automatic global deny mechanism.

BootStrap Wall3t is not a manually supervised trading console. The product is full autonomous execution inside user-authored operating policies. The user creates or links wallets, funds agent wallets intentionally, installs policies and strategy packages, and then lets agents operate without a transaction-by-transaction approval prompt.

The architecture must still answer two security questions. First, how do we keep an autonomous agent from reaching the parent wallet or long-term cold assets? Second, how do we ensure that a bad token, contract, deployer, pair, provider, or strategy family discovered by one wallet is denied everywhere else without relying on agent-to-agent communication?

The answer is three vaults and one global quarantine state. The three vaults separate credentials, automation documents, and long-term financial custody. The quarantine state is enforced below the workflow layer at the Rust wallet-core trust boundary.

This deck separates what the architecture requires, what the Rust reference now proves, and what remains to be built for production.

**Transition:** Start with the autonomy boundary, because this system is not designed around approval prompts.

## Slide 2 — Full autonomy is the product boundary

**Core message:** The product’s human-in-the-loop requirement is policy authorization, not continuous supervision.

The first principle is autonomous execution. Once an agent wallet is funded and its policy is active, the agent can trade, transfer, bootstrap, rebalance, discover targets, and retry scheduled workflows without waiting for a human click.

The second principle is user-authored policy. The user decides the operating envelope: asset scope, chain scope, contract scope, budgets, schedule, venue, slippage, and emergency behavior. These are machine-enforced definitions. They are not a platform-generated approval queue.

The third principle is one-way observation. The parent wallet can see agent balances, activity, performance, policy versions, and events. The observation relationship does not give the agent a path back into the parent wallet.

The fourth principle is the global deny state. Agents can report bad entities, and the user can report or review them. Once committed, the quarantine overrides local strategy permissions, discovery results, cached quotes, allowlists, and templates.

Agents may lose every cent held in their own wallets. That risk is intentionally different from allowing an agent to borrow from or debit the parent wallet. Autonomy is broad inside the agent wallet and sharply bounded at the custody edge.

**Transition:** Those principles become concrete when we separate the UI, automation, wallet trust, and custody planes.

## Slide 3 — Four planes, one trust boundary

**Core message:** Workflows can request actions, but only Rust wallet core can authorize execution.

The TypeScript extension is the user-facing configuration and visibility plane. It authors policies, displays discovery results, shows simulations and history, and exposes the one-way mirror. It does not store seeds and it is not a per-transaction approval queue.

The Elixir runtime is the automation plane. It supervises long-lived agents, schedules loops, retries workflows, runs discovery, and loads strategy documents. It receives opaque identifiers and scoped capabilities. It must not receive raw keys or call a signer directly.

The Rust wallet core is the trust boundary. It receives a typed intent, derives the full intent footprint, reads the authoritative quarantine state, checks policy, simulates, signs through an opaque signer, and performs the final broadcast gate.

The custody plane contains the three vaults. The Secrets Vault exposes protected signing operations. The Automations Vault stores non-signing policy and strategy material. The Financial Cold Vault is a user-side hardware-backed store outside agent authority.

This layering matters because a new workflow should inherit the quarantine guard automatically. If the guard lives only in a swap helper, the next bridge, staking, bootstrap, or discovery feature can accidentally bypass it.

**Transition:** The first vault is the credential boundary: anything capable of authenticating or signing belongs there.

## Slide 4 — Secrets Vault

**Core message:** Agents can request signing operations without receiving key material.

The Secrets Vault contains user and agent private keys, mnemonics, API keys, OAuth tokens, SSH keys, certificates, webhook secrets, and other authentication or signing material.

The allowed access pattern is deliberately narrow. The Rust wallet boundary invokes an opaque signer operation or a scoped credential adapter. The agent sees a typed result, not a private key. Elixir sees an opaque capability, not a mnemonic. The browser extension sees public addresses, policy decisions, simulations, receipts, and audit records, not raw vault contents.

The right column is as important as the contents column. The vault must never expose raw credentials to UI code or ordinary agent processes. It must never treat an automation document as authority to unlock the parent wallet. It must never reuse a service API token as wallet-signing authority.

The Rust draft already reflects this direction through the `OpaqueSigner` trait. The test signer is deterministic and synthetic. It is there to prove ordering, not to be shipped as cryptography.

Production work still needs a real Secrets Vault adapter, hardware-backed signer boundaries, reviewed derivation, memory handling, and removal of the Python mnemonic-in-request path.

**Transition:** Credentials tell the system how to authenticate. The next vault tells it what the automation is allowed to attempt.

## Slide 5 — Automations Vault

**Core message:** Automation documents define behavior but cannot manufacture financial authority.

The Automations Vault stores policies and policy versions, strategy capsules, document packages, schedules, triggers, retry behavior, workflow definitions, discovery rules, prompts, templates, and circuit-breaker configuration.

Every executable package needs a wallet or agent scope, a version, and a content hash. That lets wallet core determine which exact policy and strategy were active when an intent was produced.

The boundary is non-signing. A document can say, “run this strategy on this schedule,” but it cannot unlock the parent wallet, reach the Financial Cold Vault, or bypass the Rust policy and quarantine checks. The Elixir runtime can orchestrate the document, but the generated action still becomes a typed intent and passes through the same trust boundary.

This structure supports automation without turning configuration storage into an unrestricted treasury. It also gives us a clean place to invalidate strategy, discovery, quote, and template caches when the registry version changes.

The production registry design adds a signed checkpoint and versioned state root to this picture. A strategy activation records the registry version it saw. If the registry advances, the old activation decision is stale and must be rebuilt.

**Transition:** The third vault is intentionally outside the automation float and has a different release protocol.

## Slide 6 — Financial Cold Vault

**Core message:** Long-term user assets remain hardware-backed and unavailable to agents.

The Financial Cold Vault holds assets the user intends to keep outside the automation float. That can include long-term crypto, supported fiat or fiat claims, and carefully modeled semi-flexible staking positions.

Keys are generated and held through hardware-backed custody. Agents cannot initiate, accelerate, cancel, or redirect a cold-vault withdrawal. They may see permitted balance or public position data through the one-way supervisory mirror, but they do not get a withdrawal capability.

A withdrawal begins with user authorization, verifies the destination, starts an adjustable delay and cancellation window, and ends with an immutable audit record. The destination can be a hot wallet, an explicitly approved agent wallet, a bank, or another user-approved endpoint. The delay applies to crypto and fiat destinations.

The cold vault is not a mechanism for supervising autonomous trading. The user funds agent wallets intentionally and agents can operate autonomously with those funds. The cold vault simply remains outside their authority even if an agent has broad authority over its own wallet.

This separation must eventually be enforced as a separate principal and API, not just a different folder in a common database.

**Transition:** Now we can look at the system-wide response when any wallet discovers a bad entity.

## Slide 7 — Global quarantine: one deny state

**Core message:** A single committed report becomes a versioned deny state for every linked wallet.

The process begins when an agent or the user identifies a bad entity. The entity can be a token, contract, deployer, pair, chain, provider, wallet, or strategy family. A report includes a canonical identifier, reason, evidence references, reporter identity, and registry version context.

The report is submitted to the authoritative registry. In the production design, a quorum-replicated append-only log commits the command. The committed log index becomes the monotonic registry version. The registry then emits a signed checkpoint containing the version, log head hash, state root, and quorum certificate.

Linked wallets receive the new state through a subscription or certified read. They invalidate positive allowlist, quote, route, discovery, and strategy caches. They do not need to message one another.

The wallet core fails closed when it cannot prove a current registry state. A stale but validly signed checkpoint proves what the registry said at an earlier time; it does not prove that the checkpoint is current. That is why final sign and broadcast gates require a read barrier or equivalent freshness certificate.

Only the user can reverse the entry. That reversal is a control-plane action requiring the hardware authorization protocol described outside this deck.

**Transition:** The deny state matters only if every value-moving and authority-creating operation consumes it.

## Slide 8 — Quarantine is below every operation

**Core message:** One shared intent footprint and guard cover transfers, permissions, DeFi, payments, and automation activation.

Native and token transfers check the chain, asset, recipient, contract, and deployer context. Approvals and permits check the token, spender, operator, typed-data domain, and chain. A swap checks both assets, the router, pools, callbacks, dependencies, and deployers.

Bridges add source and destination assets, bridge contracts, relayers, and destination contracts. Staking adds the staking contract, validator or operator, token, and reward contracts. Lightning checks the invoice context, provider, destination, and asset scope before sending.

Agent-to-agent transfer, bootstrap methods, and discovery-triggered activation are not privileged bypass paths. Their generated intents include the destination and every entity they can touch. Strategy activation checks the strategy capsule, referenced venues and assets, then checks every action the strategy generates.

The Rust reference represents this with `IntentFootprint`. It sorts and deduplicates the complete entity set, then applies one guard. The same guard is used by all eleven operation kinds in the tests.

The production adapter must add chain-native canonicalization, real ABI and typed-data decoding, and dependency discovery. The architectural rule does not change: no operation gets a special path around the guard.

**Transition:** The most important tests are not happy-path swaps; they are races between registry change and execution.

## Slide 9 — Race tests close the time-of-check gap

**Core message:** A registry update between simulation, signing, and broadcast invalidates the action.

At simulation, wallet core derives the footprint and records the certified registry version in a ticket. At signing, it reads the registry again. If the version changed, the ticket is stale even if the newly added quarantine targets an unrelated entity. That conservative invalidation makes positive decisions non-reusable across registry versions.

Signing also rechecks the footprint. This catches a quarantine that targets the operation directly. Broadcast performs a final read barrier and repeats both checks. A signed payload is not automatically safe to release if the global deny state moved after signing.

The verified Rust suite covers concurrent quarantine-versus-signing and quarantine-versus-broadcast, reversal invalidating older tickets, router-only quarantine blocking a clean-token swap, an unavailable registry failing closed, and cross-wallet propagation over a shared registry.

The next production test layer injects failures into quorum reads, leader changes, replica lag, signed-checkpoint rotation, and network partitions. The acceptance criterion remains the same: a committed deny state must beat any stale positive decision, or the write must stop.

**Transition:** The result is a clear split between what is now executable and what remains a production gate.

## Slide 10 — Design aligned; implementation gates remain

**Core message:** The reference proves the trust ordering; the production store and hardware protocol are the next security gates.

The architecture is aligned with full autonomy. The Rust reference now proves the versioned registry contract, shared intent guard, stale-ticket behavior, user-only reversal shape, and race-test structure.

The reference is not a production registry. It is process-local, unsigned, unpersisted, and has no chain adapter. It cannot survive a node crash, prove quorum, authenticate a real hardware credential, or establish freshness across replicas.

The next gates are concrete. First, freeze the wallet graph, vault access matrix, and canonical entity identifiers. Second, replace the in-memory state with a quorum-committed log, durable state materializer, signed checkpoints, and read barriers. Third, implement the WebAuthn/FIDO2 hardware reversal protocol with expected-head binding and one-time challenges. Fourth, attach the guard to a real EVM testnet adapter and signer boundary. Fifth, run fault-injection and recovery tests in CI before wiring the extension and Elixir runtime to production paths.

The central product promise remains unchanged: agents operate autonomously with the funds they hold, the parent and cold vault remain outside their authority, and a single user- or agent-reported bad entity can become a global deny state without emotional or per-transaction interference.

**Closing line:** Autonomous agents, separated custody, one-way observation, and a user-controlled global deny switch are the product architecture. Durable quorum state and hardware-authorized reversal are what make that architecture production-grade.

## Reviewer questions to pre-empt

**Does a quarantine report require a human approval?** No. Agents can report and activate quarantine automatically. Human hardware authorization is required only to reverse an active quarantine.

**Does a registry outage permit old trades to continue?** No for value-moving writes. Read-only dashboards may use the last verified checkpoint, but signing and broadcast require a current read barrier and fail closed otherwise.

**Does a signed snapshot prove that it is current?** No. It proves authenticity of a historical state. The production design separates state authenticity from freshness and requires a quorum read barrier for final writes.

**Can an agent reverse its own quarantine?** No. The reversal command requires a verified user hardware credential, expected registry head, evidence review hash, and a quorum commit.

**Does reversal restore old approvals or strategy decisions?** No. Reversal advances the registry version and invalidates all older tickets and positive caches. New policy and simulation checks are required.

**What is still missing?** Durable consensus-backed storage, signed checkpoint verification, real hardware authorization, chain adapter integration, vault principals, and fault-injection evidence.

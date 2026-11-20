# BootStrap Wall3t — Deck Structure and Speaker-Notes Review

**Deck reviewed:** `BootStrap Wall3t — Three Vaults & Global Quarantine`  
**Review date:** 2026-11-20  
**Scope:** all ten slide structures and notes for slides 1–5  
**Source comparison:** `BUILD_PLAN.md`, `PRODUCTION_REGISTRY_ARCHITECTURE.md`, `BFT_QUORUM_TRADEOFFS.md`, `QUARANTINE_REVERSAL_CRYPTO_PROTOCOL.md`, `REVERSAL_PROTOCOL_SIMULATION.md`, Rust wallet-core tests, and the attached Slides XML.

## Executive finding

The ten-slide sequence is structurally sound and accurately presents the project's central separation: autonomous agents operate inside user-authored policies, while Rust remains the signing/quarantine trust boundary and the three vaults remain separate custody domains. The deck also does the important work of distinguishing the executable Rust reference from the production registry and hardware-authorization gates.

The main pacing risk is density. Slides 1–5 carry enough architecture and caveats for a technical review, but several notes read like report prose rather than spoken narration. Slides 5, 7, 8, and 9 collectively repeat registry versions, stale checkpoints, and cache invalidation. That repetition is defensible for security reviewers, but a live presentation should assign one job to each slide and move implementation caveats into the final status slide or Q&A.

## 1. Ten-slide structure review

| Slide | Current role | Accuracy | Pacing/readability | Recommendation |
|---:|---|---|---|---|
| 1 | Product frame: three vaults plus global deny | Accurate and aligned with full automation | Strong opening; slightly long note | Keep. State the product promise and preview the proof-vs-gate distinction. |
| 2 | Autonomy operating model | Accurate; correctly rejects per-transaction approval | Clear, but repeats parts of slide 1 | Keep as the explicit non-negotiable product boundary. Trim repeated quarantine detail. |
| 3 | Four planes and trust boundary | Accurate; matches Rust/Elixir/TypeScript allocation | Dense but necessary | Keep. Use the diagram to explain request vs authority, not every component. |
| 4 | Secrets Vault | Accurate; correctly includes credentials and signer isolation | Focused and concrete | Keep. Avoid implying `OpaqueSigner` is production cryptography. |
| 5 | Automations Vault | Accurate; adds version/content-hash and quorum context | Overloaded: vault semantics plus 3-vs-7 decision | Keep vault message; move most quorum detail to slide 7 or Q&A. |
| 6 | Financial Cold Vault | Accurate; user-only, delayed, hardware-backed | Good contrast with agent float | Keep. Explicitly state it is not continuous supervision. |
| 7 | Global quarantine | Accurate; production registry flow and freshness distinction | Strong security narrative | Keep as the single canonical explanation of registry/checkpoint/read barrier. |
| 8 | Operation coverage | Accurate at architecture level; implementation remains partial | Information-dense list | Keep, but narrate only representative categories and point to coverage matrix. |
| 9 | Race tests and reversal simulation | Accurate; simulator boundary is stated | Dense test inventory | Keep. Separate Rust 21-test evidence from 20-vector simulation in visual hierarchy. |
| 10 | Status and next gates | Accurate and appropriately cautious | Strong close, slightly repetitive with slide 9 | Keep as the decision slide: what is proven, what blocks production, and next sequence. |

### Structural pacing

The deck follows a useful arc: product boundary → planes → vaults → global deny → operation coverage → race evidence → release gates. It does not need additional slides. The best trim is not deletion; it is moving implementation caveats to the status slide and letting each middle slide answer one question.

A live delivery should target approximately 60–75 seconds for slides 1–2, 75–90 seconds for slides 3–6, 90 seconds for slides 7–9, and 60 seconds for slide 10. That produces a technical review of roughly 13–16 minutes before questions.

## 2. Notes review — slides 1–5

### Slide 1 — Cover

**What is working.** The note clearly rejects the wrong product framing: this is not a manually supervised trading console. It names the two core custody/quarantine questions and previews the separation between architecture, reference evidence, and production work.

**Accuracy check.** Aligned with the automation-first clarification, three-vault boundaries, and Rust trust-boundary documents. The wording that quarantine is enforced “below the workflow layer” is accurate for the Rust reference design, but should be spoken as the target/current reference boundary rather than implying all operations are already wired in production.

**Tightening.** Remove one of the two questions or shorten the paragraph about what the deck separates. Suggested spoken version: “This deck separates what the architecture requires, what the Rust reference proves, and what production still needs.”

**Gap to cover verbally.** Mention that the parent wallet has a one-way mirror into agent activity, while agents cannot pull from or borrow from the parent. That is a defining product boundary and currently lands more fully on slide 2.

### Slide 2 — Operating model

**What is working.** The note is the clearest statement of policy authorization versus continuous supervision. It correctly says agents may lose their own funded assets while remaining unable to debit or borrow from the parent.

**Accuracy check.** Fully aligned with `BUILD_PLAN.md` sections 4.2 and 8. The note correctly keeps automatic blacklist reporting free of human approval and reserves human hardware authorization for reversal.

**Tightening.** Four principles are useful, but the fourth repeats slide 1 and previews slide 7. Keep one sentence: “A committed quarantine overrides local permissions without agent-to-agent coordination.” Move the detailed cache and registry language to slide 7.

**Gap to cover verbally.** Clarify that policy controls are user-authored machine-enforced bounds, not platform-imposed per-trade loss rails. This preserves the project's intentional risk model for agent-held funds.

### Slide 3 — System topology

**What is working.** The note accurately assigns TypeScript to UI/policy/visibility, Elixir to supervision/scheduling/workflows, Rust to typed intent and signing, and the custody plane to the three vaults. It also explains why a shared lower guard is safer than operation-specific checks.

**Accuracy check.** Matches the language allocation and Rust implementation. The phrase “reads the authoritative quarantine state” describes the production target; the current Rust reference uses the registry trait and the Elixir stub uses a local projection. It should be framed as the boundary contract, not a claim that the durable service exists.

**Tightening.** The note can lose one sentence from each plane description. Keep the contrast: “Elixir can request; Rust decides.” That should be the memorable line.

**Gap to cover verbally.** The Elixir management layer now has a reference implementation with supervised agent lifecycle, immutable flow hashes, capability expiry, idempotency-keyed run history, and fail-closed quarantine pre-flight. It still cannot sign or broadcast. This is a useful current-progress update not present in the original note.

### Slide 4 — Secrets Vault

**What is working.** The contents and prohibitions are precise. The note correctly states that opaque signing is a reference boundary and that the deterministic test signer is not production cryptography.

**Accuracy check.** Aligned with the Secrets Vault requirements and the Rust `OpaqueSigner` trait. The statement that the Rust wallet boundary “invokes” an opaque signer is a target interface; the current code has the trait and synthetic signer boundary, not a hardware-backed adapter.

**Tightening.** Keep the list of credential classes on the slide, but speak only three examples. Spend the saved time on what never crosses the boundary: seeds, private keys, raw keystore bytes, and unrestricted signer handles.

**Gap to cover verbally.** Add the Python prototype blocker: mnemonic/key material must not enter an HTTP signing request. This connects the vault rule to a concrete migration reason without overloading the slide.

### Slide 5 — Automations Vault

**What is working.** The core message is accurate: documents and policies define behavior, but cannot manufacture authority. Version, wallet/agent scope, and content hash are exactly the right production identity fields.

**Accuracy check.** The cache invalidation and registry-version statement matches the production registry design. The 3-node versus 7-node explanation matches the BFT decision record: 3-node Raft is crash-fault only; 7-node BFT supports `f = 2` only with a real BFT protocol and 5-of-7 certificate.

**Pacing risk.** This is the most overloaded slide. It covers vault content, policy identity, cache invalidation, registry versioning, and quorum architecture. The quorum paragraph is correct but too detailed for the vault slide.

**Tightening.** End after “new policy and simulation checks are required.” Move the 3-vs-7 paragraph to slide 7's production-registry explanation or reserve it for Q&A. If retained, reduce it to one sentence: “The target registry is seven-node BFT with 5-of-7 certificates; three-node Raft remains a labelled crash-fault tier.”

**Gap to cover verbally.** State that the Elixir runtime can load and orchestrate Automations Vault content, but every value-moving step becomes a typed Rust intent and inherits the same global quarantine guard.

## 3. Repetition and handoff fixes

- Slide 1 introduces global deny; slide 2 should not re-explain cache invalidation.
- Slide 3 introduces the trust boundary; slide 4 should use it rather than restating all layers.
- Slide 5 introduces versioned automation identity; slide 7 owns the detailed checkpoint/read-barrier explanation.
- Slide 9 owns evidence and race behavior; slide 10 should summarize the remaining production gates without repeating the vector inventory.

## 4. Recommended note edits

The current notes are accurate enough to retain in the attached deck. The recommended edit is a light tightening rather than a rewrite:

1. Keep slide 1's product framing and add one-way parent-to-agent observation.
2. Trim slide 2's quarantine details.
3. Add the current Elixir reference-slice status to slide 3.
4. Tie slide 4 to the concrete Python mnemonic-in-request blocker.
5. Reduce slide 5's quorum paragraph to one sentence and move its details to the registry slide/Q&A.

No slide-order change is required. No new slide is required. The deck is structurally ready for technical review with the caveat that all “production” language must remain clearly labelled as target design until the gates close.
